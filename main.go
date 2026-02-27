package main

import (
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/lieyan/warp-proxies/internal/engine"
	"github.com/lieyan/warp-proxies/internal/store"
	"github.com/lieyan/warp-proxies/internal/warp"
	"github.com/lieyan/warp-proxies/internal/web"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
)

var version = "dev"

func main() {
	var (
		dataDir string
		showVer bool
	)

	flag.StringVar(&dataDir, "data", "data", "data directory path")
	flag.BoolVar(&showVer, "version", false, "show version")
	flag.Parse()

	if showVer {
		fmt.Println("warp-proxies", version)
		return
	}

	slog.Info("starting warp-proxies", "version", version)

	// Initialize store (auto-creates settings.json on first run)
	s, err := store.New(dataDir)
	if err != nil {
		slog.Error("init store", "err", err)
		os.Exit(1)
	}

	settings := s.GetSettings()

	// Initialize WARP client
	warpClient := warp.NewClient()

	// Initialize engine
	eng := engine.New(func() (*option.Options, error) {
		accounts := s.GetEnabledAccounts()
		st := s.GetSettings()
		return engine.BuildOptions(accounts, st)
	})

	// Start engine
	if err := eng.Start(); err != nil {
		slog.Error("start engine", "err", err)
		os.Exit(1)
	}

	// Start rotator if random mode
	if settings.RotationMode == "random" {
		startRotator(eng, s)
	}

	// Start WebUI
	handler := web.NewHandler(s, eng, warpClient)
	srv := web.NewServer(settings.WebAddr, settings.WebUser, settings.WebPass, handler)

	go func() {
		if err := srv.ListenAndServe(); err != nil {
			slog.Error("WebUI server error", "err", err)
		}
	}()

	slog.Info("proxy endpoints ready",
		"socks", fmt.Sprintf("%s:%d", settings.ProxyHost, settings.SocksPort),
		"http", fmt.Sprintf("%s:%d", settings.ProxyHost, settings.HTTPPort),
		"webui", settings.WebAddr,
	)

	// Wait for signal
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	sig := <-sigCh
	slog.Info("received signal, shutting down", "signal", sig)

	if err := eng.Stop(); err != nil {
		slog.Error("stop engine", "err", err)
	}
}

func startRotator(eng *engine.Engine, s *store.Store) {
	settings := s.GetSettings()
	accounts := s.GetEnabledAccounts()
	var wgTags []string
	for _, a := range accounts {
		wgTags = append(wgTags, fmt.Sprintf("wg-%s", a.Name))
	}
	rotator := engine.NewRotator(
		"random",
		time.Duration(settings.RandomInterval)*time.Second,
		wgTags,
		func() adapter.OutboundManager {
			b := eng.Box()
			if b == nil {
				return nil
			}
			return b.Outbound()
		},
	)
	eng.SetRotator(rotator)
	rotator.Start()
}
