package web

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/lieyan/warp-proxies/internal/engine"
	"github.com/lieyan/warp-proxies/internal/store"
	"github.com/lieyan/warp-proxies/internal/warp"
	"github.com/sagernet/sing-box/adapter"
)

type Handler struct {
	store      *store.Store
	engine     *engine.Engine
	warpClient *warp.Client
}

func NewHandler(s *store.Store, e *engine.Engine, w *warp.Client) *Handler {
	return &Handler{store: s, engine: e, warpClient: w}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func (h *Handler) GetStatus(w http.ResponseWriter, r *http.Request) {
	accounts := h.store.GetEnabledAccounts()
	settings := h.store.GetSettings()

	status := map[string]any{
		"running":        h.engine.IsRunning(),
		"mode":           settings.RotationMode,
		"account_count":  len(accounts),
		"current":        "",
	}

	b := h.engine.Box()
	if b != nil {
		status["current"] = engine.GetCurrentOutbound(b.Outbound())
	}

	writeJSON(w, http.StatusOK, status)
}

func (h *Handler) GetAccounts(w http.ResponseWriter, r *http.Request) {
	accounts := h.store.GetAccounts()
	// Redact sensitive fields
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

	// Restart engine to pick up new account
	go func() {
		if err := h.engine.Restart(); err != nil {
			slog.Error("restart engine after add", "err", err)
		}
	}()

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

		// Sleep between registrations to avoid rate limiting
		if i < req.Count-1 {
			time.Sleep(2 * time.Second)
		}
	}

	// Restart engine
	go func() {
		if err := h.engine.Restart(); err != nil {
			slog.Error("restart engine after batch add", "err", err)
		}
	}()

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

	// Restart engine
	go func() {
		if err := h.engine.Restart(); err != nil {
			slog.Error("restart engine after delete", "err", err)
		}
	}()

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
		writeError(w, http.StatusInternalServerError, "update account: "+err.Error())
		return
	}

	if needRestart {
		go func() {
			if err := h.engine.Restart(); err != nil {
				slog.Error("restart engine after update", "err", err)
			}
		}()
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "updated"})
}

func (h *Handler) GetSettings(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, h.store.GetSettings())
}

func (h *Handler) UpdateSettings(w http.ResponseWriter, r *http.Request) {
	var settings store.Settings
	if err := json.NewDecoder(r.Body).Decode(&settings); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if err := h.store.SetSettings(settings); err != nil {
		writeError(w, http.StatusInternalServerError, "save settings: "+err.Error())
		return
	}

	// Restart engine to apply new settings
	go func() {
		if err := h.engine.Restart(); err != nil {
			slog.Error("restart engine after settings update", "err", err)
		}
	}()

	writeJSON(w, http.StatusOK, map[string]string{"status": "updated"})
}

func (h *Handler) RestartEngine(w http.ResponseWriter, r *http.Request) {
	go func() {
		if err := h.engine.Restart(); err != nil {
			slog.Error("manual engine restart", "err", err)
		}
	}()
	writeJSON(w, http.StatusOK, map[string]string{"status": "restarting"})
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
	if mode != "urltest" && mode != "random" {
		writeError(w, http.StatusBadRequest, "mode must be 'urltest' or 'random'")
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

	var outboundMgr adapter.OutboundManager = b.Outbound()
	if !engine.SwitchMode(outboundMgr, mode, wgTags) {
		writeError(w, http.StatusInternalServerError, "failed to switch mode")
		return
	}

	// Update settings
	settings := h.store.GetSettings()
	settings.RotationMode = mode
	h.store.SetSettings(settings)

	// Update rotator
	if mode == "random" {
		rotator := engine.NewRotator(
			"random",
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
