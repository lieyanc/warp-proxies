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
		dataDir    string
		socksPort  uint
		httpPort   uint
		webAddr    string
		socksUser  string
		socksPass  string
		webUser    string
		webPass    string
		showVer    bool
	)

	flag.StringVar(&dataDir, "data", "data", "data directory path")
	flag.UintVar(&socksPort, "socks-port", 1080, "SOCKS5 proxy listen port")
	flag.UintVar(&httpPort, "http-port", 8080, "HTTP proxy listen port")
	flag.StringVar(&webAddr, "web-addr", ":9090", "WebUI listen address")
	flag.StringVar(&socksUser, "proxy-user", "", "proxy authentication username")
	flag.StringVar(&socksPass, "proxy-pass", "", "proxy authentication password")
	flag.StringVar(&webUser, "web-user", "admin", "WebUI basic auth username")
	flag.StringVar(&webPass, "web-pass", "admin", "WebUI basic auth password")
	flag.BoolVar(&showVer, "version", false, "show version")
	flag.Parse()

	if showVer {
		fmt.Println("warp-proxies", version)
		return
	}

	slog.Info("starting warp-proxies", "version", version)

	// Initialize store
	s, err := store.New(dataDir)
	if err != nil {
		slog.Error("init store", "err", err)
		os.Exit(1)
	}

	// Initialize WARP client
	warpClient := warp.NewClient()

	// Initialize engine
	eng := engine.New(func() (*option.Options, error) {
		accounts := s.GetEnabledAccounts()
		settings := s.GetSettings()
		return engine.BuildOptions(accounts, settings, uint16(socksPort), uint16(httpPort), socksUser, socksPass)
	})

	// Start engine
	if err := eng.Start(); err != nil {
		slog.Error("start engine", "err", err)
		os.Exit(1)
	}

	// Start rotator if random mode
	settings := s.GetSettings()
	if settings.RotationMode == "random" {
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

	// Start WebUI
	handler := web.NewHandler(s, eng, warpClient)
	srv := web.NewServer(webAddr, webUser, webPass, handler)

	go func() {
		if err := srv.ListenAndServe(); err != nil {
			slog.Error("WebUI server error", "err", err)
		}
	}()

	slog.Info("proxy endpoints ready",
		"socks", fmt.Sprintf(":%d", socksPort),
		"http", fmt.Sprintf(":%d", httpPort),
		"webui", webAddr,
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
