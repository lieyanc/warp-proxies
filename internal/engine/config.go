package engine

import (
	"fmt"
	"net/netip"
	"time"

	"github.com/lieyan/warp-proxies/internal/store"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/auth"
	"github.com/sagernet/sing/common/json/badoption"
)

func BuildOptions(accounts []store.Account, settings store.Settings) (*option.Options, error) {
	proxyHost := settings.ProxyHost
	if proxyHost == "" {
		proxyHost = "127.0.0.1"
	}
	listenAddr := badoption.Addr(netip.MustParseAddr(proxyHost))

	var inbounds []option.Inbound

	// SOCKS5 inbound
	socksOpts := &option.SocksInboundOptions{
		ListenOptions: option.ListenOptions{
			Listen:     &listenAddr,
			ListenPort: settings.SocksPort,
		},
	}
	if settings.ProxyUser != "" {
		socksOpts.Users = []auth.User{{Username: settings.ProxyUser, Password: settings.ProxyPass}}
	}
	inbounds = append(inbounds, option.Inbound{
		Type:    C.TypeSOCKS,
		Tag:     "socks-in",
		Options: socksOpts,
	})

	// HTTP Mixed inbound
	httpOpts := &option.HTTPMixedInboundOptions{
		ListenOptions: option.ListenOptions{
			Listen:     &listenAddr,
			ListenPort: settings.HTTPPort,
		},
	}
	if settings.ProxyUser != "" {
		httpOpts.Users = []auth.User{{Username: settings.ProxyUser, Password: settings.ProxyPass}}
	}
	inbounds = append(inbounds, option.Inbound{
		Type:    C.TypeMixed,
		Tag:     "http-in",
		Options: httpOpts,
	})

	// Outbounds
	var outbounds []option.Outbound

	// Direct outbound
	outbounds = append(outbounds, option.Outbound{
		Type:    C.TypeDirect,
		Tag:     "direct",
		Options: &option.DirectOutboundOptions{},
	})

	// WireGuard outbounds for each enabled account
	var wgTags []string
	tagCount := make(map[string]int)
	for _, acc := range accounts {
		baseTag := fmt.Sprintf("wg-%s", acc.Name)
		tagCount[baseTag]++
		tag := baseTag
		if tagCount[baseTag] > 1 {
			tag = fmt.Sprintf("%s-%d", baseTag, tagCount[baseTag])
		}
		wgTags = append(wgTags, tag)

		ipv4, err := netip.ParsePrefix(acc.IPv4)
		if err != nil {
			return nil, fmt.Errorf("parse IPv4 for %s: %w", acc.Name, err)
		}

		var addresses []netip.Prefix
		addresses = append(addresses, ipv4)
		if acc.IPv6 != "" {
			ipv6, err := netip.ParsePrefix(acc.IPv6)
			if err == nil {
				addresses = append(addresses, ipv6)
			}
		}

		wgOpts := &option.LegacyWireGuardOutboundOptions{
			DialerOptions: option.DialerOptions{
				// Resolve WireGuard endpoint hostname via DoH (direct),
				// bypassing any local fake-IP DNS interception.
				DomainResolver: &option.DomainResolveOptions{
					Server: "dns-endpoint",
				},
			},
			ServerOptions: option.ServerOptions{
				Server:     acc.Endpoint,
				ServerPort: acc.EndpointPort,
			},
			LocalAddress:  addresses,
			PrivateKey:    acc.PrivateKey,
			PeerPublicKey: acc.PeerPublicKey,
			Reserved:      acc.Reserved,
			MTU:           1280,
			Workers:       1,
		}

		outbounds = append(outbounds, option.Outbound{
			Type:    C.TypeWireGuard,
			Tag:     tag,
			Options: wgOpts,
		})
	}

	// URLTest group
	if len(wgTags) > 0 {
		urltestOpts := &option.URLTestOutboundOptions{
			Outbounds:                 wgTags,
			URL:                       settings.URLTestURL,
			Interval:                  badoption.Duration(time.Duration(settings.URLTestInterval) * time.Second),
			Tolerance:                 settings.URLTestTolerance,
			InterruptExistConnections: true,
		}
		outbounds = append(outbounds, option.Outbound{
			Type:    C.TypeURLTest,
			Tag:     "auto",
			Options: urltestOpts,
		})

		// Selector group: includes "auto" + all individual WG tags
		selectorTags := []string{"auto"}
		selectorTags = append(selectorTags, wgTags...)

		defaultTag := "auto"
		if settings.RotationMode == "random" {
			defaultTag = wgTags[0]
		}

		selectorOpts := &option.SelectorOutboundOptions{
			Outbounds:                 selectorTags,
			Default:                   defaultTag,
			InterruptExistConnections: true,
		}
		outbounds = append(outbounds, option.Outbound{
			Type:    C.TypeSelector,
			Tag:     "proxy",
			Options: selectorOpts,
		})
	} else {
		// No accounts: selector with direct
		outbounds = append(outbounds, option.Outbound{
			Type: C.TypeSelector,
			Tag:  "proxy",
			Options: &option.SelectorOutboundOptions{
				Outbounds:                 []string{"direct"},
				Default:                   "direct",
				InterruptExistConnections: true,
			},
		})
	}

	// DNS configuration:
	// Two DNS servers with different purposes:
	// - "dns-endpoint": DoH via 1.1.1.1, direct outbound. Used ONLY by
	//   WireGuard outbounds to resolve endpoint hostnames (e.g.
	//   engage.cloudflareclient.com). Avoids fake-IP interception from
	//   local proxy tools.
	// - "dns-proxy": UDP 1.1.1.1, through "proxy" outbound. Default
	//   resolver for proxied traffic — DNS queries go through the WARP
	//   tunnel so DNS is not leaked to the local network.
	dnsOpts := &option.DNSOptions{
		RawDNSOptions: option.RawDNSOptions{
			Servers: []option.DNSServerOptions{
				{
					Type: C.DNSTypeHTTPS,
					Tag:  "dns-endpoint",
					Options: &option.RemoteHTTPSDNSServerOptions{
						RemoteTLSDNSServerOptions: option.RemoteTLSDNSServerOptions{
							RemoteDNSServerOptions: option.RemoteDNSServerOptions{
								LocalDNSServerOptions: option.LocalDNSServerOptions{
									DialerOptions: option.DialerOptions{
										Detour: "direct",
									},
								},
								DNSServerAddressOptions: option.DNSServerAddressOptions{
									Server: "1.1.1.1",
								},
							},
						},
					},
				},
				{
					Type: "udp",
					Tag:  "dns-proxy",
					Options: &option.RemoteDNSServerOptions{
						LocalDNSServerOptions: option.LocalDNSServerOptions{
							DialerOptions: option.DialerOptions{
								Detour: "proxy",
							},
						},
						DNSServerAddressOptions: option.DNSServerAddressOptions{
							Server: "1.1.1.1",
						},
					},
				},
			},
			Final: "dns-proxy",
		},
	}

	// Route
	routeOpts := &option.RouteOptions{
		Final:               "proxy",
		AutoDetectInterface: true,
	}

	// Experimental: Clash API
	var experimental *option.ExperimentalOptions
	if settings.ClashAPIPort > 0 {
		experimental = &option.ExperimentalOptions{
			ClashAPI: &option.ClashAPIOptions{
				ExternalController: fmt.Sprintf("127.0.0.1:%d", settings.ClashAPIPort),
				Secret:             settings.ClashAPISecret,
				DefaultMode:        "Rule",
			},
			CacheFile: &option.CacheFileOptions{
				Enabled: true,
			},
		}
	}

	opts := &option.Options{
		Log: &option.LogOptions{
			Level:     "info",
			Timestamp: true,
		},
		Inbounds:     inbounds,
		Outbounds:    outbounds,
		DNS:          dnsOpts,
		Route:        routeOpts,
		Experimental: experimental,
	}

	return opts, nil
}
