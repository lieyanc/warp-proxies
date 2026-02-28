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

// ErrNoAccounts is returned by BuildOptions when there are no enabled accounts.
var ErrNoAccounts = fmt.Errorf("no enabled accounts")

// WGTagForAccount returns the sing-box outbound tag for the account with the given ID.
// enabledAccounts must be in the same order as returned by store.GetEnabledAccounts().
// The algorithm mirrors BuildOptions exactly so tag assignments are always consistent,
// including the shared-outer case where multiple inners point to the same outer ID.
func WGTagForAccount(enabledAccounts []store.Account, accountID string) string {
	outerIDSet := make(map[string]bool)
	accountByID := make(map[string]store.Account)
	for _, acc := range enabledAccounts {
		accountByID[acc.ID] = acc
		if acc.GoolOuterID != "" {
			outerIDSet[acc.GoolOuterID] = true
		}
	}

	tagCount := make(map[string]int)
	createdOuterTags := make(map[string]string) // outerID → assigned tag

	for _, acc := range enabledAccounts {
		if outerIDSet[acc.ID] {
			continue
		}

		if acc.GoolOuterID != "" {
			outerAcc, outerFound := accountByID[acc.GoolOuterID]

			innerBaseTag := fmt.Sprintf("wg-%s", acc.Name)
			tagCount[innerBaseTag]++
			innerTag := innerBaseTag
			if tagCount[innerBaseTag] > 1 {
				innerTag = fmt.Sprintf("%s-%d", innerBaseTag, tagCount[innerBaseTag])
			}

			if outerFound {
				outerTag, alreadyCreated := createdOuterTags[acc.GoolOuterID]
				if !alreadyCreated {
					outerBaseTag := fmt.Sprintf("wg-%s-outer", outerAcc.Name)
					tagCount[outerBaseTag]++
					outerTag = outerBaseTag
					if tagCount[outerBaseTag] > 1 {
						outerTag = fmt.Sprintf("%s-%d", outerBaseTag, tagCount[outerBaseTag])
					}
					createdOuterTags[acc.GoolOuterID] = outerTag
				}
				if outerAcc.ID == accountID {
					return outerTag
				}
			}

			if acc.ID == accountID {
				return innerTag
			}
		} else {
			baseTag := fmt.Sprintf("wg-%s", acc.Name)
			tagCount[baseTag]++
			tag := baseTag
			if tagCount[baseTag] > 1 {
				tag = fmt.Sprintf("%s-%d", baseTag, tagCount[baseTag])
			}
			if acc.ID == accountID {
				return tag
			}
		}
	}
	return ""
}

// SelectorTagsForAccounts returns the outbound tags that should be included in the
// URLTest/Selector/RoundRobin groups. Gool outer accounts are excluded.
func SelectorTagsForAccounts(accounts []store.Account) []string {
	outerIDSet := make(map[string]bool)
	for _, acc := range accounts {
		if acc.GoolOuterID != "" {
			outerIDSet[acc.GoolOuterID] = true
		}
	}

	tagCount := make(map[string]int)
	var tags []string
	for _, acc := range accounts {
		if outerIDSet[acc.ID] {
			continue
		}
		baseTag := fmt.Sprintf("wg-%s", acc.Name)
		tagCount[baseTag]++
		tag := baseTag
		if tagCount[baseTag] > 1 {
			tag = fmt.Sprintf("%s-%d", baseTag, tagCount[baseTag])
		}
		tags = append(tags, tag)
	}
	return tags
}

// buildWGOutboundOptions creates a LegacyWireGuardOutboundOptions for the given account.
// mtu: 1280 for single/inner, 1330 for gool outer.
// detour: outbound tag to route UDP through; empty means direct.
// workers: number of concurrent packet workers (scale with inner count for outer).
func buildWGOutboundOptions(acc store.Account, mtu uint32, detour string, workers int) (*option.LegacyWireGuardOutboundOptions, error) {
	ipv4, err := netip.ParsePrefix(acc.IPv4)
	if err != nil {
		return nil, fmt.Errorf("parse IPv4 for %s: %w", acc.Name, err)
	}

	var addresses []netip.Prefix
	addresses = append(addresses, ipv4)
	if acc.IPv6 != "" {
		if ipv6, err := netip.ParsePrefix(acc.IPv6); err == nil {
			addresses = append(addresses, ipv6)
		}
	}

	dialerOpts := option.DialerOptions{
		// Resolve WireGuard endpoint hostname via DoH (direct),
		// bypassing any local fake-IP DNS interception.
		DomainResolver: &option.DomainResolveOptions{
			Server: "dns-endpoint",
		},
	}
	if detour != "" {
		dialerOpts.Detour = detour
	}

	return &option.LegacyWireGuardOutboundOptions{
		DialerOptions: dialerOpts,
		ServerOptions: option.ServerOptions{
			Server:     acc.Endpoint,
			ServerPort: acc.EndpointPort,
		},
		LocalAddress:  addresses,
		PrivateKey:    acc.PrivateKey,
		PeerPublicKey: acc.PeerPublicKey,
		Reserved:      acc.Reserved,
		MTU:           mtu,
		Workers:       workers,
	}, nil
}

func BuildOptions(accounts []store.Account, settings store.Settings) (*option.Options, error) {
	if len(accounts) == 0 {
		return nil, ErrNoAccounts
	}

	// Pre-scan: identify gool roles and build lookup maps.
	accountByID := make(map[string]store.Account)
	outerIDSet := make(map[string]bool)
	innerCountPerOuter := make(map[string]int) // outerID → number of inners using it
	for _, acc := range accounts {
		accountByID[acc.ID] = acc
		if acc.GoolOuterID != "" {
			outerIDSet[acc.GoolOuterID] = true
			innerCountPerOuter[acc.GoolOuterID]++
		}
	}

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
	var selectorTags []string
	tagCount := make(map[string]int)
	createdOuterTags := make(map[string]string) // outerID → assigned outbound tag

	for _, acc := range accounts {
		if outerIDSet[acc.ID] {
			// Outer accounts are emitted when we encounter the first inner that
			// references them, preserving tag-assignment order.
			continue
		}

		if acc.GoolOuterID != "" {
			// Gool inner account.
			outerAcc, outerFound := accountByID[acc.GoolOuterID]

			innerBaseTag := fmt.Sprintf("wg-%s", acc.Name)
			tagCount[innerBaseTag]++
			innerTag := innerBaseTag
			if tagCount[innerBaseTag] > 1 {
				innerTag = fmt.Sprintf("%s-%d", innerBaseTag, tagCount[innerBaseTag])
			}

			var detour string
			if outerFound {
				outerTag, alreadyCreated := createdOuterTags[acc.GoolOuterID]
				if !alreadyCreated {
					// First inner referencing this outer: emit the outer outbound.
					outerBaseTag := fmt.Sprintf("wg-%s-outer", outerAcc.Name)
					tagCount[outerBaseTag]++
					outerTag = outerBaseTag
					if tagCount[outerBaseTag] > 1 {
						outerTag = fmt.Sprintf("%s-%d", outerBaseTag, tagCount[outerBaseTag])
					}

					// Scale outer workers with inner count (capped at 4).
					workers := innerCountPerOuter[outerAcc.ID]
					if workers < 1 {
						workers = 1
					} else if workers > 4 {
						workers = 4
					}

					outerWGOpts, err := buildWGOutboundOptions(outerAcc, 1330, "", workers)
					if err != nil {
						return nil, err
					}
					outbounds = append(outbounds, option.Outbound{
						Type:    C.TypeWireGuard,
						Tag:     outerTag,
						Options: outerWGOpts,
					})
					createdOuterTags[acc.GoolOuterID] = outerTag
				}
				detour = outerTag
			}

			// Inner outbound: MTU=1280, routes through outer (or direct if outer unavailable).
			innerWGOpts, err := buildWGOutboundOptions(acc, 1280, detour, 1)
			if err != nil {
				return nil, err
			}
			outbounds = append(outbounds, option.Outbound{
				Type:    C.TypeWireGuard,
				Tag:     innerTag,
				Options: innerWGOpts,
			})
			selectorTags = append(selectorTags, innerTag)
		} else {
			// Regular single account.
			baseTag := fmt.Sprintf("wg-%s", acc.Name)
			tagCount[baseTag]++
			tag := baseTag
			if tagCount[baseTag] > 1 {
				tag = fmt.Sprintf("%s-%d", baseTag, tagCount[baseTag])
			}

			wgOpts, err := buildWGOutboundOptions(acc, 1280, "", 1)
			if err != nil {
				return nil, err
			}
			outbounds = append(outbounds, option.Outbound{
				Type:    C.TypeWireGuard,
				Tag:     tag,
				Options: wgOpts,
			})
			selectorTags = append(selectorTags, tag)
		}
	}

	if len(selectorTags) == 0 {
		return nil, ErrNoAccounts
	}

	if settings.RotationMode == "roundrobin" {
		// Per-connection round-robin: custom outbound cycles through all WG
		// outbounds atomically on each DialContext call. No URLTest needed.
		outbounds = append(outbounds, option.Outbound{
			Type:    TypeRoundRobin,
			Tag:     "proxy",
			Options: &RoundRobinOptions{Outbounds: selectorTags},
		})
	} else {
		// URLTest group (used by urltest and random modes)
		urltestOpts := &option.URLTestOutboundOptions{
			Outbounds:                 selectorTags,
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
		selTags := []string{"auto"}
		selTags = append(selTags, selectorTags...)

		defaultTag := "auto"
		if settings.RotationMode == "random" {
			defaultTag = selectorTags[0]
		}

		selectorOpts := &option.SelectorOutboundOptions{
			Outbounds:                 selTags,
			Default:                   defaultTag,
			InterruptExistConnections: true,
		}
		outbounds = append(outbounds, option.Outbound{
			Type:    C.TypeSelector,
			Tag:     "proxy",
			Options: selectorOpts,
		})
	}

	// DNS configuration:
	// - "dns-endpoint": DoH via 1.1.1.1, direct outbound. Used ONLY by
	//   WireGuard outbounds to resolve endpoint hostnames. Avoids fake-IP interception.
	// - "dns-proxy": UDP 1.1.1.1, through "proxy" outbound. Default resolver
	//   for proxied traffic so DNS is not leaked to the local network.
	dnsOpts := &option.DNSOptions{
		RawDNSOptions: option.RawDNSOptions{
			Servers: []option.DNSServerOptions{
				{
					Type: C.DNSTypeHTTPS,
					Tag:  "dns-endpoint",
					Options: &option.RemoteHTTPSDNSServerOptions{
						RemoteTLSDNSServerOptions: option.RemoteTLSDNSServerOptions{
							RemoteDNSServerOptions: option.RemoteDNSServerOptions{
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
