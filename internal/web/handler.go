package web

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/lieyan/warp-proxies/internal/engine"
	"github.com/lieyan/warp-proxies/internal/store"
	"github.com/lieyan/warp-proxies/internal/warp"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/protocol/group"
)

type Handler struct {
	store      *store.Store
	engine     *engine.Engine
	warpClient *warp.Client
	version    string
	binDir     string
	ipCheckMu  sync.Mutex
}

func NewHandler(s *store.Store, e *engine.Engine, w *warp.Client, version, binDir string) *Handler {
	return &Handler{store: s, engine: e, warpClient: w, version: version, binDir: binDir}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func (h *Handler) Login(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (h *Handler) GetStatus(w http.ResponseWriter, r *http.Request) {
	accounts := h.store.GetEnabledAccounts()
	settings := h.store.GetSettings()

	status := map[string]any{
		"running":       h.engine.IsRunning(),
		"mode":          settings.RotationMode,
		"account_count": len(accounts),
		"current":       "",
	}

	b := h.engine.Box()
	if b != nil {
		status["current"] = engine.GetCurrentOutbound(b.Outbound())
	}

	writeJSON(w, http.StatusOK, status)
}

func (h *Handler) GetAccounts(w http.ResponseWriter, r *http.Request) {
	accounts := h.store.GetAccounts()
	type safeAccount struct {
		ID            string    `json:"id"`
		Name          string    `json:"name"`
		PublicKey     string    `json:"public_key"`
		PeerPublicKey string    `json:"peer_public_key"`
		Endpoint      string    `json:"endpoint"`
		EndpointPort  uint16    `json:"endpoint_port"`
		IPv4          string    `json:"ipv4"`
		IPv6          string    `json:"ipv6"`
		Enabled       bool      `json:"enabled"`
		CreatedAt     time.Time `json:"created_at"`
	}

	safe := make([]safeAccount, len(accounts))
	for i, a := range accounts {
		safe[i] = safeAccount{
			ID:            a.ID,
			Name:          a.Name,
			PublicKey:     a.PublicKey,
			PeerPublicKey: a.PeerPublicKey,
			Endpoint:      a.Endpoint,
			EndpointPort:  a.EndpointPort,
			IPv4:          a.IPv4,
			IPv6:          a.IPv6,
			Enabled:       a.Enabled,
			CreatedAt:     a.CreatedAt,
		}
	}

	writeJSON(w, http.StatusOK, safe)
}

func (h *Handler) CreateAccount(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name         string `json:"name"`
		Endpoint     string `json:"endpoint"`
		EndpointPort uint16 `json:"endpoint_port"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.Name == "" {
		req.Name = fmt.Sprintf("warp-%d", len(h.store.GetAccounts())+1)
	}

	account, err := h.warpClient.Register(req.Name, req.Endpoint, req.EndpointPort)
	if err != nil {
		slog.Error("register WARP account", "err", err)
		writeError(w, http.StatusInternalServerError, "registration failed: "+err.Error())
		return
	}

	if err := h.store.AddAccount(*account); err != nil {
		writeError(w, http.StatusInternalServerError, "save account: "+err.Error())
		return
	}

	slog.Info("registered WARP account", "name", account.Name, "id", account.ID)

	go h.restartEngine()

	writeJSON(w, http.StatusCreated, map[string]string{
		"id":   account.ID,
		"name": account.Name,
	})
}

func (h *Handler) BatchCreateAccounts(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Count        int    `json:"count"`
		Endpoint     string `json:"endpoint"`
		EndpointPort uint16 `json:"endpoint_port"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Count <= 0 || req.Count > 20 {
		writeError(w, http.StatusBadRequest, "count must be between 1 and 20")
		return
	}

	existing := len(h.store.GetAccounts())
	var results []map[string]string

	for i := 0; i < req.Count; i++ {
		name := fmt.Sprintf("warp-%d", existing+i+1)
		account, err := h.warpClient.Register(name, req.Endpoint, req.EndpointPort)
		if err != nil {
			slog.Error("batch register failed", "index", i, "err", err)
			results = append(results, map[string]string{
				"name":  name,
				"error": err.Error(),
			})
			continue
		}

		if err := h.store.AddAccount(*account); err != nil {
			results = append(results, map[string]string{
				"name":  name,
				"error": "save: " + err.Error(),
			})
			continue
		}

		results = append(results, map[string]string{
			"id":   account.ID,
			"name": account.Name,
		})

		slog.Info("batch registered WARP account", "name", account.Name, "id", account.ID)

		if i < req.Count-1 {
			time.Sleep(2 * time.Second)
		}
	}

	go h.restartEngine()

	writeJSON(w, http.StatusCreated, results)
}

func (h *Handler) DeleteAccount(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		writeError(w, http.StatusBadRequest, "missing account id")
		return
	}

	account, found, err := h.store.RemoveAccount(id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "remove account: "+err.Error())
		return
	}
	if !found {
		writeError(w, http.StatusNotFound, "account not found")
		return
	}

	// Try to delete from CF (best effort)
	go func() {
		if err := h.warpClient.Delete(account.ID, account.Token); err != nil {
			slog.Warn("failed to delete account from CF", "id", account.ID, "err", err)
		}
	}()

	go h.restartEngine()

	slog.Info("deleted WARP account", "name", account.Name, "id", account.ID)
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

func (h *Handler) UpdateAccount(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		writeError(w, http.StatusBadRequest, "missing account id")
		return
	}

	var req struct {
		Name         *string `json:"name"`
		Enabled      *bool   `json:"enabled"`
		Endpoint     *string `json:"endpoint"`
		EndpointPort *uint16 `json:"endpoint_port"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	needRestart := false
	err := h.store.UpdateAccount(id, func(a *store.Account) {
		if req.Name != nil {
			a.Name = *req.Name
			needRestart = true
		}
		if req.Enabled != nil {
			a.Enabled = *req.Enabled
			needRestart = true
		}
		if req.Endpoint != nil {
			a.Endpoint = *req.Endpoint
			needRestart = true
		}
		if req.EndpointPort != nil {
			a.EndpointPort = *req.EndpointPort
			needRestart = true
		}
	})
	if err != nil {
		if errors.Is(err, store.ErrAccountNotFound) {
			writeError(w, http.StatusNotFound, "account not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "update account: "+err.Error())
		return
	}

	if needRestart {
		go h.restartEngine()
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "updated"})
}

func (h *Handler) GetSettings(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, h.store.GetSettings())
}

func (h *Handler) UpdateSettings(w http.ResponseWriter, r *http.Request) {
	settings := h.store.GetSettings()
	if err := json.NewDecoder(r.Body).Decode(&settings); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if err := h.store.SetSettings(settings); err != nil {
		writeError(w, http.StatusInternalServerError, "save settings: "+err.Error())
		return
	}

	go h.restartEngine()

	writeJSON(w, http.StatusOK, map[string]string{"status": "updated"})
}

func (h *Handler) RestartEngine(w http.ResponseWriter, r *http.Request) {
	go h.restartEngine()
	writeJSON(w, http.StatusOK, map[string]string{"status": "restarting"})
}

// restartEngine restarts the sing-box engine and re-creates the rotator if needed.
func (h *Handler) restartEngine() {
	h.engine.Restart()
	if !h.engine.IsRunning() {
		return
	}
	settings := h.store.GetSettings()
	if !engine.IsRotatingMode(settings.RotationMode) {
		return
	}
	accounts := h.store.GetEnabledAccounts()
	var wgTags []string
	for _, a := range accounts {
		wgTags = append(wgTags, fmt.Sprintf("wg-%s", a.Name))
	}
	if len(wgTags) == 0 {
		return
	}
	rotator := engine.NewRotator(
		settings.RotationMode,
		time.Duration(settings.RandomInterval)*time.Second,
		wgTags,
		func() adapter.OutboundManager {
			bx := h.engine.Box()
			if bx == nil {
				return nil
			}
			return bx.Outbound()
		},
	)
	h.engine.SetRotator(rotator)
	rotator.Start()
}

func (h *Handler) SwitchMode(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Mode string `json:"mode"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	mode := strings.ToLower(req.Mode)
	if mode != "urltest" && mode != "random" && mode != "roundrobin" {
		writeError(w, http.StatusBadRequest, "mode must be 'urltest', 'random', or 'roundrobin'")
		return
	}

	b := h.engine.Box()
	if b == nil {
		writeError(w, http.StatusServiceUnavailable, "engine not running")
		return
	}

	// Build WG tags from enabled accounts
	accounts := h.store.GetEnabledAccounts()
	var wgTags []string
	for _, a := range accounts {
		wgTags = append(wgTags, fmt.Sprintf("wg-%s", a.Name))
	}

	if len(wgTags) == 0 {
		writeError(w, http.StatusBadRequest, "no enabled accounts")
		return
	}

	engine.SwitchMode(b.Outbound(), mode, wgTags)

	// Persist mode change
	settings := h.store.GetSettings()
	settings.RotationMode = mode
	if err := h.store.SetSettings(settings); err != nil {
		slog.Error("persist mode switch", "err", err)
	}

	// Update rotator
	if engine.IsRotatingMode(mode) {
		rotator := engine.NewRotator(
			mode,
			time.Duration(settings.RandomInterval)*time.Second,
			wgTags,
			func() adapter.OutboundManager {
				bx := h.engine.Box()
				if bx == nil {
					return nil
				}
				return bx.Outbound()
			},
		)
		h.engine.SetRotator(rotator)
		rotator.Start()
	} else {
		h.engine.SetRotator(nil)
	}

	slog.Info("switched rotation mode", "mode", mode)
	writeJSON(w, http.StatusOK, map[string]string{"status": "switched", "mode": mode})
}

func (h *Handler) GetVersion(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"version": h.version})
}

func (h *Handler) CheckUpdate(w http.ResponseWriter, r *http.Request) {
	settings := h.store.GetSettings()
	channel := settings.UpdateChannel
	if channel == "" {
		channel = "dev"
	}

	const repo = "lieyanc/warp-proxies"
	var apiURL string
	if channel == "stable" {
		apiURL = "https://api.github.com/repos/" + repo + "/releases/latest"
	} else {
		apiURL = "https://api.github.com/repos/" + repo + "/releases/tags/dev"
	}

	client := &http.Client{Timeout: 10 * time.Second}
	req, _ := http.NewRequestWithContext(r.Context(), "GET", apiURL, nil)
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := client.Do(req)
	if err != nil {
		writeError(w, http.StatusBadGateway, "failed to check update: "+err.Error())
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil || resp.StatusCode != 200 {
		writeError(w, http.StatusBadGateway, "GitHub API error")
		return
	}

	var release struct {
		Name    string `json:"name"`
		TagName string `json:"tag_name"`
	}
	if err := json.Unmarshal(body, &release); err != nil {
		writeError(w, http.StatusBadGateway, "failed to parse release info")
		return
	}

	var latest string
	if channel == "stable" {
		latest = release.TagName
	} else {
		// name: "Dev Build (dev-0005-20260227-abc1234)"
		if start := strings.Index(release.Name, "("); start != -1 {
			if end := strings.Index(release.Name[start:], ")"); end != -1 {
				latest = release.Name[start+1 : start+end]
			}
		}
		if latest == "" {
			latest = release.TagName
		}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"current":    h.version,
		"latest":     latest,
		"channel":    channel,
		"has_update": latest != "" && latest != h.version,
	})
}

func (h *Handler) TriggerUpdate(w http.ResponseWriter, r *http.Request) {
	script := filepath.Join(h.binDir, "start.sh")

	cmd := exec.Command("bash", script)
	cmd.Dir = h.binDir
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}

	if err := cmd.Start(); err != nil {
		slog.Error("trigger update failed", "err", err)
		writeError(w, http.StatusInternalServerError, "failed to start update: "+err.Error())
		return
	}

	go cmd.Wait()

	slog.Info("update triggered", "pid", cmd.Process.Pid)
	writeJSON(w, http.StatusOK, map[string]string{"status": "updating"})
}

func (h *Handler) CheckAccountIP(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		writeError(w, http.StatusBadRequest, "missing account id")
		return
	}

	b := h.engine.Box()
	if b == nil {
		writeError(w, http.StatusServiceUnavailable, "engine not running")
		return
	}

	// Resolve the WG outbound tag for this account
	enabledAccounts := h.store.GetEnabledAccounts()
	wgTag := engine.WGTagForAccount(enabledAccounts, id)
	if wgTag == "" {
		for _, a := range h.store.GetAccounts() {
			if a.ID == id {
				writeError(w, http.StatusBadRequest, "account is disabled")
				return
			}
		}
		writeError(w, http.StatusNotFound, "account not found")
		return
	}

	// Lock so concurrent checks don't clobber each other's selector state
	h.ipCheckMu.Lock()
	defer h.ipCheckMu.Unlock()

	proxyOut, ok := b.Outbound().Outbound("proxy")
	if !ok {
		writeError(w, http.StatusInternalServerError, "proxy outbound not found")
		return
	}
	sel, ok := proxyOut.(*group.Selector)
	if !ok {
		writeError(w, http.StatusInternalServerError, "proxy outbound is not a selector")
		return
	}

	prevTag := sel.Now()
	if !sel.SelectOutbound(wgTag) {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("failed to select outbound %s", wgTag))
		return
	}
	defer sel.SelectOutbound(prevTag)

	// Route a request through the local HTTP proxy port
	settings := h.store.GetSettings()
	proxyHost := settings.ProxyHost
	if proxyHost == "" || proxyHost == "0.0.0.0" {
		proxyHost = "127.0.0.1"
	}
	proxyURL, _ := url.Parse(fmt.Sprintf("http://%s:%d", proxyHost, settings.HTTPPort))
	if settings.ProxyUser != "" {
		proxyURL.User = url.UserPassword(settings.ProxyUser, settings.ProxyPass)
	}

	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()

	client := &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)},
		Timeout:   15 * time.Second,
	}

	req, err := http.NewRequestWithContext(ctx, "GET", "https://api.ipify.org?format=json", nil)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "build request: "+err.Error())
		return
	}

	resp, err := client.Do(req)
	if err != nil {
		writeError(w, http.StatusBadGateway, "IP check failed: "+err.Error())
		return
	}
	defer resp.Body.Close()

	var result struct {
		IP string `json:"ip"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 256)).Decode(&result); err != nil {
		writeError(w, http.StatusBadGateway, "parse response: "+err.Error())
		return
	}

	slog.Info("IP check", "account_id", id, "tag", wgTag, "ip", result.IP)
	writeJSON(w, http.StatusOK, map[string]string{"ip": result.IP})
}

func (h *Handler) StreamLogs(w http.ResponseWriter, r *http.Request) {
	logPath := filepath.Join(h.binDir, "warp-proxies.log")

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming not supported", http.StatusInternalServerError)
		return
	}

	f, err := os.Open(logPath)
	if err != nil {
		fmt.Fprintf(w, "data: [log file not found: warp-proxies.log]\n\n")
		flusher.Flush()
		return
	}
	defer f.Close()

	// Seek to last ~16KB so the client sees recent history immediately
	const tailBytes int64 = 16 * 1024
	if info, err := f.Stat(); err == nil && info.Size() > tailBytes {
		f.Seek(-tailBytes, io.SeekEnd)
		// Discard the partial first line
		oneByte := make([]byte, 1)
		for {
			n, err := f.Read(oneByte)
			if err != nil || n == 0 || oneByte[0] == '\n' {
				break
			}
		}
	}

	ctx := r.Context()
	buf := make([]byte, 4096)
	var pending []byte

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		n, readErr := f.Read(buf)
		if n > 0 {
			pending = append(pending, buf[:n]...)
			for {
				idx := bytes.IndexByte(pending, '\n')
				if idx < 0 {
					break
				}
				line := bytes.TrimRight(pending[:idx], "\r")
				pending = pending[idx+1:]
				fmt.Fprintf(w, "data: %s\n\n", line)
			}
			flusher.Flush()
		}
		if readErr == io.EOF {
			select {
			case <-ctx.Done():
				return
			case <-time.After(300 * time.Millisecond):
			}
		} else if readErr != nil {
			return
		}
	}
}
