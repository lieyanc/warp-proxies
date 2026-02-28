package warp

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/lieyan/warp-proxies/internal/store"
)

const (
	apiBase       = "https://api.cloudflareclient.com/v0a1922/reg"
	userAgent     = "okhttp/3.12.1"
	clientVersion = "a-6.3-1922"
)

type Client struct {
	httpClient *http.Client
}

func NewClient() *Client {
	return &Client{
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					MinVersion: tls.VersionTLS12,
				},
			},
		},
	}
}

func (c *Client) Register(name string, endpoint string, endpointPort uint16) (*store.Account, error) {
	kp, err := GenerateKeyPair()
	if err != nil {
		return nil, fmt.Errorf("generate key pair: %w", err)
	}

	reqBody := RegisterRequest{
		Key:       kp.PublicKey,
		InstallID: "",
		FCMToken:  "",
		Tos:       time.Now().UTC().Format("2006-01-02T15:04:05.000Z"),
		Model:     "PC",
		Type:      "Android",
		Locale:    "en_US",
	}

	body, err := json.Marshal(reqBody)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("POST", apiBase, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("CF-Client-Version", clientVersion)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("register request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("register failed (status %d): %s", resp.StatusCode, string(respBody))
	}

	var regResp RegisterResponse
	if err := json.Unmarshal(respBody, &regResp); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}

	reserved, err := decodeClientID(regResp.Config.ClientID)
	if err != nil {
		return nil, fmt.Errorf("decode client_id: %w", err)
	}

	var peerPubKey string
	if len(regResp.Config.Peers) > 0 {
		peerPubKey = regResp.Config.Peers[0].PublicKey
	}

	if endpoint == "" {
		endpoint = "engage.cloudflareclient.com"
	}
	if endpointPort == 0 {
		endpointPort = 2408
	}

	account := &store.Account{
		ID:            regResp.ID,
		Name:          name,
		PrivateKey:    kp.PrivateKey,
		PublicKey:     kp.PublicKey,
		PeerPublicKey: peerPubKey,
		Endpoint:      endpoint,
		EndpointPort:  endpointPort,
		IPv4:          ensureCIDR(regResp.Config.Interface.Addresses.V4, "/32"),
		IPv6:          ensureCIDR(regResp.Config.Interface.Addresses.V6, "/128"),
		Reserved:      reserved,
		Token:         regResp.Token,
		Enabled:       true,
		CreatedAt:     time.Now().UTC(),
	}

	return account, nil
}

// RegisterGoolPair registers one outer + one inner WARP account pair.
// The inner's GoolOuterID is set to the outer's ID so it routes through it.
func (c *Client) RegisterGoolPair(name, endpoint string, port uint16) (*store.Account, *store.Account, error) {
	outer, err := c.Register(name+"-outer", endpoint, port)
	if err != nil {
		return nil, nil, fmt.Errorf("register outer: %w", err)
	}
	time.Sleep(time.Second)
	inner, err := c.Register(name, endpoint, port)
	if err != nil {
		return outer, nil, fmt.Errorf("register inner: %w", err)
	}
	inner.GoolOuterID = outer.ID
	return outer, inner, nil
}

// RegisterGoolBatch registers pairCount independent gool pairs.
// Each pair has its own outer account so exit IPs are distinct per pair.
// For pairCount == 1 the pair is named (baseName-outer, baseName).
// For pairCount > 1 pairs are named (baseName-1-outer, baseName-1), …, (baseName-N-outer, baseName-N).
func (c *Client) RegisterGoolBatch(baseName string, pairCount int, endpoint string, port uint16) ([]*store.Account, []*store.Account, error) {
	var outers, inners []*store.Account
	for i := 1; i <= pairCount; i++ {
		pairName := baseName
		if pairCount > 1 {
			pairName = fmt.Sprintf("%s-%d", baseName, i)
		}
		outer, inner, err := c.RegisterGoolPair(pairName, endpoint, port)
		if outer != nil {
			outers = append(outers, outer)
		}
		if inner != nil {
			inners = append(inners, inner)
		}
		if err != nil {
			return outers, inners, fmt.Errorf("register pair %d: %w", i, err)
		}
		if i < pairCount {
			time.Sleep(time.Second)
		}
	}
	return outers, inners, nil
}

func (c *Client) Delete(id, token string) error {
	req, err := http.NewRequest("DELETE", apiBase+"/"+id, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("CF-Client-Version", clientVersion)
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("delete request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("delete failed (status %d): %s", resp.StatusCode, string(body))
	}

	return nil
}

func decodeClientID(clientID string) ([]uint8, error) {
	decoded, err := base64.StdEncoding.DecodeString(clientID)
	if err != nil {
		return nil, err
	}
	if len(decoded) < 3 {
		return nil, fmt.Errorf("client_id too short: %d bytes", len(decoded))
	}
	return []uint8{decoded[0], decoded[1], decoded[2]}, nil
}

// ensureCIDR appends the default suffix if addr has no '/' prefix length.
func ensureCIDR(addr, defaultSuffix string) string {
	if addr == "" {
		return ""
	}
	if !strings.Contains(addr, "/") {
		return addr + defaultSuffix
	}
	return addr
}
