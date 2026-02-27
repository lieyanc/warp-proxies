package web

import (
	"embed"
	"io/fs"
	"log/slog"
	"net/http"
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

	// API routes
	mux.HandleFunc("GET /api/status", s.handler.GetStatus)
	mux.HandleFunc("GET /api/accounts", s.handler.GetAccounts)
	mux.HandleFunc("POST /api/accounts", s.handler.CreateAccount)
	mux.HandleFunc("POST /api/accounts/batch", s.handler.BatchCreateAccounts)
	mux.HandleFunc("DELETE /api/accounts/{id}", s.handler.DeleteAccount)
	mux.HandleFunc("PATCH /api/accounts/{id}", s.handler.UpdateAccount)
	mux.HandleFunc("GET /api/settings", s.handler.GetSettings)
	mux.HandleFunc("PUT /api/settings", s.handler.UpdateSettings)
	mux.HandleFunc("POST /api/engine/restart", s.handler.RestartEngine)
	mux.HandleFunc("POST /api/engine/mode", s.handler.SwitchMode)

	// Static files
	staticContent, _ := fs.Sub(staticFS, "static")
	fileServer := http.FileServer(http.FS(staticContent))
	mux.Handle("/", fileServer)

	var handler http.Handler = mux
	if s.user != "" {
		handler = s.basicAuth(mux)
	}

	// CORS wrapper
	handler = s.cors(handler)

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
		if !ok || user != s.user || pass != s.pass {
			w.Header().Set("WWW-Authenticate", `Basic realm="warp-proxies"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
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
