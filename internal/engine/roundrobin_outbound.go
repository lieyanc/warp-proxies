package engine

import (
	"context"
	"net"
	"sync/atomic"

	"github.com/sagernet/sing-box/adapter"
	adapterOutbound "github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/log"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
)

// TypeRoundRobin is the sing-box outbound type name for per-connection round-robin.
const TypeRoundRobin = "roundrobin"

// RoundRobinOptions is the configuration for a RoundRobin outbound.
type RoundRobinOptions struct {
	Outbounds []string `json:"outbounds"`
}

// RegisterRoundRobin registers the RoundRobin outbound type with a sing-box outbound registry.
func RegisterRoundRobin(registry *adapterOutbound.Registry) {
	adapterOutbound.Register[RoundRobinOptions](registry, TypeRoundRobin, NewRoundRobin)
}

// RoundRobin is a sing-box outbound group that routes each new connection to
// the next outbound in the list, cycling atomically. This provides true
// per-connection round-robin with no shared state races.
type RoundRobin struct {
	adapterOutbound.Adapter
	outboundMgr adapter.OutboundManager
	tags        []string
	outbounds   []adapter.Outbound
	index       atomic.Uint64
}

var (
	_ adapter.Outbound      = (*RoundRobin)(nil)
	_ adapter.OutboundGroup = (*RoundRobin)(nil)
)

func NewRoundRobin(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options RoundRobinOptions) (adapter.Outbound, error) {
	if len(options.Outbounds) == 0 {
		return nil, E.New("missing outbounds")
	}
	return &RoundRobin{
		Adapter:     adapterOutbound.NewAdapter(TypeRoundRobin, tag, []string{N.NetworkTCP, N.NetworkUDP}, options.Outbounds),
		outboundMgr: service.FromContext[adapter.OutboundManager](ctx),
		tags:        options.Outbounds,
	}, nil
}

// Start resolves outbound references after sing-box initializes all outbounds.
// Called by the sing-box outbound manager during startup.
func (r *RoundRobin) Start() error {
	r.outbounds = make([]adapter.Outbound, 0, len(r.tags))
	for i, tag := range r.tags {
		out, loaded := r.outboundMgr.Outbound(tag)
		if !loaded {
			return E.New("outbound ", i, " not found: ", tag)
		}
		r.outbounds = append(r.outbounds, out)
	}
	return nil
}

func (r *RoundRobin) next() adapter.Outbound {
	idx := r.index.Add(1) - 1
	return r.outbounds[int(idx)%len(r.outbounds)]
}

func (r *RoundRobin) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	return r.next().DialContext(ctx, network, destination)
}

func (r *RoundRobin) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return r.next().ListenPacket(ctx, destination)
}

// Now returns the next outbound tag to be used. Implements adapter.OutboundGroup.
func (r *RoundRobin) Now() string {
	if len(r.outbounds) == 0 {
		if len(r.tags) == 0 {
			return ""
		}
		return r.tags[0]
	}
	idx := r.index.Load()
	return r.outbounds[int(idx)%len(r.outbounds)].Tag()
}

// All returns all managed outbound tags. Implements adapter.OutboundGroup.
func (r *RoundRobin) All() []string {
	return r.tags
}
