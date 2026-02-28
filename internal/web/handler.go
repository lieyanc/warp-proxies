package web

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/lieyan/warp-proxies/internal/engine"
	"github.com/lieyan/warp-proxies/internal/store"
	"github.com/lieyan/warp-proxies/internal/warp"
	"github.com/sagernet/sing-box/adapter"
	M "github.com/sagernet/sing/common/metadata"
)

type Handler struct {
	store      *store.Store
	engine     *engine.Engine
	warpClient *warp.Client
	version    string
	binDir     string
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
		GoolOuterID   string    `json:"gool_outer_id,omitempty"`
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
			GoolOuterID:   a.GoolOuterID,
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

	writeJSON(w, http.StatusCreated, results)
}

func (h *Handler) CreateGoolPair(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name         string `json:"name"`
		Count        int    `json:"count"`
		Endpoint     string `json:"endpoint"`
		EndpointPort uint16 `json:"endpoint_port"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Name == "" {
		writeError(w, http.StatusBadRequest, "name is required")
		return
	}
	if req.Count <= 0 {
		req.Count = 1
	}
	if req.Count > 10 {
		req.Count = 10
	}

	outer, inners, err := h.warpClient.RegisterGoolBatch(req.Name, req.Count, req.Endpoint, req.EndpointPort)
	if err != nil {
		slog.Error("register gool batch", "err", err)
		writeError(w, http.StatusInternalServerError, "registration failed: "+err.Error())
		return
	}

	if err := h.store.AddAccount(*outer); err != nil {
		writeError(w, http.StatusInternalServerError, "save outer account: "+err.Error())
		return
	}
	for _, inner := range inners {
		if err := h.store.AddAccount(*inner); err != nil {
			slog.Error("save inner account", "name", inner.Name, "err", err)
		}
	}

	slog.Info("registered gool group", "name", req.Name, "inners", len(inners), "outer_id", outer.ID)
	writeJSON(w, http.StatusCreated, map[string]any{"outer": outer, "inners": inners})
}

// AddGoolInners registers count new inner accounts for an existing outer account.
func (h *Handler) AddGoolInners(w http.ResponseWriter, r *http.Request) {
	outerID := r.PathValue("id")
	if outerID == "" {
		writeError(w, http.StatusBadRequest, "missing outer account id")
		return
	}

	var req struct {
		Count        int    `json:"count"`
		Endpoint     string `json:"endpoint"`
		EndpointPort uint16 `json:"endpoint_port"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Count <= 0 {
		req.Count = 1
	}
	if req.Count > 10 {
		req.Count = 10
	}

	outerAcc, found := h.store.GetAccountByID(outerID)
	if !found {
		writeError(w, http.StatusNotFound, "outer account not found")
		return
	}

	// Derive base name from outer (strip "-outer" suffix if present).
	baseName := strings.TrimSuffix(outerAcc.Name, "-outer")

	// Starting index for new inner names based on existing inner count.
	existingInners := h.store.FindInnersByOuterID(outerID)
	startIdx := len(existingInners) + 1

	var results []*store.Account
	for i := 0; i < req.Count; i++ {
		innerName := fmt.Sprintf("%s-%d", baseName, startIdx+i)
		inner, err := h.warpClient.RegisterGoolInner(outerID, innerName, req.Endpoint, req.EndpointPort)
		if err != nil {
			slog.Error("register gool inner", "index", i, "err", err)
			break
		}
		if err := h.store.AddAccount(*inner); err != nil {
			slog.Error("save gool inner", "name", inner.Name, "err", err)
		}
		results = append(results, inner)
		if i < req.Count-1 {
			time.Sleep(time.Second)
		}
	}

	if len(results) == 0 {
		writeError(w, http.StatusInternalServerError, "failed to register any inner accounts")
		return
	}

	slog.Info("added gool inners", "outer_id", outerID, "count", len(results))
	writeJSON(w, http.StatusCreated, map[string]any{"inners": results})
}

func (h *Handler) DeleteAccount(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		writeError(w, http.StatusBadRequest, "missing account id")
		return
	}

	allAccounts := h.store.GetAccounts()

	// Collect all inners if this is an outer being deleted (cascade).
	var innerIDs []string
	var goolOuterID string
	for _, a := range allAccounts {
		if a.GoolOuterID == id {
			innerIDs = append(innerIDs, a.ID)
		}
		if a.ID == id {
			goolOuterID = a.GoolOuterID
		}
	}

	// Cascade-delete all inners first (if this is an outer).
	var deletedInners []store.Account
	for _, innerID := range innerIDs {
		inner, found, _ := h.store.RemoveAccount(innerID)
		if found {
			deletedInners = append(deletedInners, inner)
		}
	}

	// Delete the target account itself.
	account, found, err := h.store.RemoveAccount(id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "remove account: "+err.Error())
		return
	}
	if !found {
		writeError(w, http.StatusNotFound, "account not found")
		return
	}

	// If this was an inner, clean up its outer if it has become orphaned.
	var orphanedOuter store.Account
	var orphanFound bool
	if goolOuterID != "" {
		remaining := 0
		for _, a := range h.store.GetAccounts() {
			if a.GoolOuterID == goolOuterID {
				remaining++
			}
		}
		if remaining == 0 {
			orphanedOuter, orphanFound, _ = h.store.RemoveAccount(goolOuterID)
		}
	}

	// Best-effort CF deletions.
	go func() {
		if err := h.warpClient.Delete(account.ID, account.Token); err != nil {
			slog.Warn("failed to delete account from CF", "id", account.ID, "err", err)
		}
		for _, inner := range deletedInners {
			if err := h.warpClient.Delete(inner.ID, inner.Token); err != nil {
				slog.Warn("failed to delete inner from CF", "id", inner.ID, "err", err)
			}
		}
		if orphanFound {
			if err := h.warpClient.Delete(orphanedOuter.ID, orphanedOuter.Token); err != nil {
				slog.Warn("failed to delete orphaned outer from CF", "id", orphanedOuter.ID, "err", err)
			}
		}
	}()

	slog.Info("deleted WARP account", "name", account.Name, "id", account.ID,
		"cascade_inners", len(deletedInners), "orphan_outer_cleaned", orphanFound)
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

	err := h.store.UpdateAccount(id, func(a *store.Account) {
		if req.Name != nil {
			a.Name = *req.Name
		}
		if req.Enabled != nil {
			a.Enabled = *req.Enabled
		}
		if req.Endpoint != nil {
			a.Endpoint = *req.Endpoint
		}
		if req.EndpointPort != nil {
			a.EndpointPort = *req.EndpointPort
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
	wgTags := engine.SelectorTagsForAccounts(accounts)
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

	settings := h.store.GetSettings()
	settings.RotationMode = mode
	if err := h.store.SetSettings(settings); err != nil {
		slog.Error("persist mode switch", "err", err)
		writeError(w, http.StatusInternalServerError, "save settings: "+err.Error())
		return
	}

	slog.Info("saved rotation mode (pending restart)", "mode", mode)
	writeJSON(w, http.StatusOK, map[string]string{"status": "saved", "mode": mode})
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

	wgOut, loaded := b.Outbound().Outbound(wgTag)
	if !loaded {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("WireGuard outbound %s not found", wgTag))
		return
	}

	// Dial directly through the WireGuard outbound. This avoids any interaction
	// with the "proxy" Selector/RoundRobin and works regardless of rotation mode.
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()

	client := &http.Client{
		Transport: &http.Transport{
			DialContext: func(dialCtx context.Context, network, addr string) (net.Conn, error) {
				return wgOut.DialContext(dialCtx, network, M.ParseSocksaddr(addr))
			},
		},
		Timeout: 15 * time.Second,
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
