package engine

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
)

type Engine struct {
	mu        sync.Mutex
	box       *box.Box
	running   bool
	buildOpts func() (*option.Options, error)
	rotator   *Rotator
}

func New(buildOpts func() (*option.Options, error)) *Engine {
	return &Engine{
		buildOpts: buildOpts,
	}
}

func (e *Engine) Start() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.startLocked()
}

func (e *Engine) startLocked() error {
	opts, err := e.buildOpts()
	if err != nil {
		if errors.Is(err, ErrNoAccounts) {
			slog.Info("no enabled accounts, engine idle")
			return nil
		}
		return fmt.Errorf("build options: %w", err)
	}

	ctx := include.Context(context.Background())

	instance, err := box.New(box.Options{
		Context: ctx,
		Options: *opts,
	})
	if err != nil {
		return fmt.Errorf("create box: %w", err)
	}

	if err := instance.Start(); err != nil {
		instance.Close()
		return fmt.Errorf("start box: %w", err)
	}

	e.box = instance
	e.running = true
	slog.Info("sing-box engine started")
	return nil
}

func (e *Engine) Stop() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.stopLocked()
}

func (e *Engine) stopLocked() error {
	if e.rotator != nil {
		e.rotator.Stop()
		e.rotator = nil
	}
	if e.box != nil {
		err := e.box.Close()
		e.box = nil
		e.running = false
		slog.Info("sing-box engine stopped")
		return err
	}
	return nil
}

func (e *Engine) Restart() {
	e.mu.Lock()
	defer e.mu.Unlock()
	if err := e.stopLocked(); err != nil {
		slog.Warn("error stopping engine", "err", err)
	}
	if err := e.startLocked(); err != nil {
		slog.Error("error starting engine", "err", err)
	}
}

func (e *Engine) IsRunning() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.running
}

func (e *Engine) Box() *box.Box {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.box
}

func (e *Engine) SetRotator(r *Rotator) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.rotator != nil {
		e.rotator.Stop()
	}
	e.rotator = r
}

func (e *Engine) Rotator() *Rotator {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.rotator
}
