package web

import (
	"embed"
	"encoding/base64"
	"io/fs"
	"log/slog"
	"net/http"
	"strings"
)

//go:embed static
var staticFS embed.FS

type Server struct {
	handler *Handler
	addr    string
	user    string
	pass    string
}

func NewServer(addr, user, pass string, handler *Handler) *Server {
	return &Server{
		handler: handler,
		addr:    addr,
		user:    user,
		pass:    pass,
	}
}

func (s *Server) ListenAndServe() error {
	mux := http.NewServeMux()

	// API routes (protected by auth)
	apiMux := http.NewServeMux()
	apiMux.HandleFunc("POST /api/login", s.handler.Login)
	apiMux.HandleFunc("GET /api/status", s.handler.GetStatus)
	apiMux.HandleFunc("GET /api/accounts", s.handler.GetAccounts)
	apiMux.HandleFunc("POST /api/accounts", s.handler.CreateAccount)
	apiMux.HandleFunc("POST /api/accounts/batch", s.handler.BatchCreateAccounts)
	apiMux.HandleFunc("POST /api/accounts/gool", s.handler.CreateGoolPair)
	apiMux.HandleFunc("POST /api/accounts/gool/{id}/inner", s.handler.AddGoolInners)
	apiMux.HandleFunc("DELETE /api/accounts/{id}", s.handler.DeleteAccount)
	apiMux.HandleFunc("PATCH /api/accounts/{id}", s.handler.UpdateAccount)
	apiMux.HandleFunc("GET /api/accounts/{id}/ip", s.handler.CheckAccountIP)
	apiMux.HandleFunc("GET /api/settings", s.handler.GetSettings)
	apiMux.HandleFunc("PUT /api/settings", s.handler.UpdateSettings)
	apiMux.HandleFunc("POST /api/engine/restart", s.handler.RestartEngine)
	apiMux.HandleFunc("POST /api/engine/mode", s.handler.SwitchMode)
	apiMux.HandleFunc("GET /api/version", s.handler.GetVersion)
	apiMux.HandleFunc("GET /api/update/check", s.handler.CheckUpdate)
	apiMux.HandleFunc("POST /api/update", s.handler.TriggerUpdate)
	apiMux.HandleFunc("GET /api/logs", s.handler.StreamLogs)

	if s.user != "" {
		mux.Handle("/api/", s.basicAuth(apiMux))
	} else {
		mux.Handle("/api/", apiMux)
	}

	// Static files (no auth)
	staticContent, _ := fs.Sub(staticFS, "static")
	fileServer := http.FileServer(http.FS(staticContent))
	mux.Handle("/", fileServer)

	// CORS wrapper
	handler := s.cors(mux)

	slog.Info("WebUI server starting", "addr", s.addr)
	return http.ListenAndServe(s.addr, handler)
}

func (s *Server) basicAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Skip auth for CORS preflight
		if r.Method == "OPTIONS" {
			next.ServeHTTP(w, r)
			return
		}

		user, pass, ok := r.BasicAuth()

		// EventSource (SSE) cannot send custom headers; accept ?auth= query param as fallback
		if !ok {
			if authParam := r.URL.Query().Get("auth"); authParam != "" {
				if decoded, err := base64.StdEncoding.DecodeString(authParam); err == nil {
					if parts := strings.SplitN(string(decoded), ":", 2); len(parts) == 2 {
						user, pass, ok = parts[0], parts[1], true
					}
				}
			}
		}

		if !ok || user != s.user || pass != s.pass {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) cors(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin != "" {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
			w.Header().Set("Access-Control-Allow-Credentials", "true")
		}
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}
