package engine

import (
	"log/slog"
	"math/rand/v2"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/protocol/group"
)

type Rotator struct {
	mu       sync.Mutex
	mode     string // "urltest" or "random"
	interval time.Duration
	tags     []string
	getBox   func() adapter.OutboundManager
	stopCh   chan struct{}
	stopped  bool
}

func NewRotator(mode string, interval time.Duration, tags []string, getBox func() adapter.OutboundManager) *Rotator {
	return &Rotator{
		mode:     mode,
		interval: interval,
		tags:     tags,
		getBox:   getBox,
		stopCh:   make(chan struct{}),
	}
}

func (r *Rotator) Start() {
	if r.mode != "random" || len(r.tags) == 0 {
		return
	}
	go r.run()
}

func (r *Rotator) run() {
	ticker := time.NewTicker(r.interval)
	defer ticker.Stop()

	for {
		select {
		case <-r.stopCh:
			return
		case <-ticker.C:
			r.rotate()
		}
	}
}

func (r *Rotator) rotate() {
	outboundMgr := r.getBox()
	if outboundMgr == nil {
		return
	}

	proxyOut, ok := outboundMgr.Outbound("proxy")
	if !ok {
		return
	}

	selector, ok := proxyOut.(*group.Selector)
	if !ok {
		slog.Warn("proxy outbound is not a selector")
		return
	}

	tag := r.tags[rand.IntN(len(r.tags))]
	if selector.SelectOutbound(tag) {
		slog.Info("rotated to outbound", "tag", tag)
	}
}

func (r *Rotator) Stop() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.stopped {
		close(r.stopCh)
		r.stopped = true
	}
}

func (r *Rotator) Mode() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.mode
}

// SwitchMode switches the rotation mode at runtime.
// For "urltest": select "auto" in the selector
// For "random": select a random individual tag
func SwitchMode(outboundMgr adapter.OutboundManager, mode string, wgTags []string) bool {
	proxyOut, ok := outboundMgr.Outbound("proxy")
	if !ok {
		return false
	}

	selector, ok := proxyOut.(*group.Selector)
	if !ok {
		return false
	}

	switch mode {
	case "urltest":
		return selector.SelectOutbound("auto")
	case "random":
		if len(wgTags) == 0 {
			return false
		}
		tag := wgTags[rand.IntN(len(wgTags))]
		return selector.SelectOutbound(tag)
	}
	return false
}

func GetCurrentOutbound(outboundMgr adapter.OutboundManager) string {
	proxyOut, ok := outboundMgr.Outbound("proxy")
	if !ok {
		return ""
	}
	if grp, ok := proxyOut.(adapter.OutboundGroup); ok {
		return grp.Now()
	}
	return proxyOut.Tag()
}
