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
// Returns "" if the account is not found in the list.
// The algorithm mirrors BuildOptions so that tag assignments are always consistent.
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
	for _, acc := range enabledAccounts {
		if outerIDSet[acc.ID] {
			// Outer accounts are processed when we encounter their inner account.
			continue
		}

		if acc.GoolOuterID != "" {
			// Gool inner account: compute both inner and outer tags (mirrors BuildOptions).
			outerAcc, outerFound := accountByID[acc.GoolOuterID]

			innerBaseTag := fmt.Sprintf("wg-%s", acc.Name)
			tagCount[innerBaseTag]++
			innerTag := innerBaseTag
			if tagCount[innerBaseTag] > 1 {
				innerTag = fmt.Sprintf("%s-%d", innerBaseTag, tagCount[innerBaseTag])
			}

			if outerFound {
				outerBaseTag := fmt.Sprintf("wg-%s-outer", outerAcc.Name)
				tagCount[outerBaseTag]++
				outerTag := outerBaseTag
				if tagCount[outerBaseTag] > 1 {
					outerTag = fmt.Sprintf("%s-%d", outerBaseTag, tagCount[outerBaseTag])
				}
				if outerAcc.ID == accountID {
					return outerTag
				}
			}

			if acc.ID == accountID {
				return innerTag
			}
		} else {
			// Regular single account.
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
// mtu is the WireGuard MTU (1280 for single/inner, 1330 for gool outer).
// detour is the outbound tag to route WireGuard UDP through; empty means direct.
func buildWGOutboundOptions(acc store.Account, mtu uint32, detour string) (*option.LegacyWireGuardOutboundOptions, error) {
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
		Workers:       1,
	}, nil
}

func BuildOptions(accounts []store.Account, settings store.Settings) (*option.Options, error) {
	if len(accounts) == 0 {
		return nil, ErrNoAccounts
	}

	// Pre-scan: identify outer accounts and build lookup map.
	accountByID := make(map[string]store.Account)
	outerIDSet := make(map[string]bool)
	for _, acc := range accounts {
		accountByID[acc.ID] = acc
		if acc.GoolOuterID != "" {
			outerIDSet[acc.GoolOuterID] = true
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

	for _, acc := range accounts {
		if outerIDSet[acc.ID] {
			// Outer accounts are created when we process their paired inner account.
			continue
		}

		if acc.GoolOuterID != "" {
			// Gool inner account: create both outer and inner outbounds.
			outerAcc, outerFound := accountByID[acc.GoolOuterID]

			// Inner tag
			innerBaseTag := fmt.Sprintf("wg-%s", acc.Name)
			tagCount[innerBaseTag]++
			innerTag := innerBaseTag
			if tagCount[innerBaseTag] > 1 {
				innerTag = fmt.Sprintf("%s-%d", innerBaseTag, tagCount[innerBaseTag])
			}

			if outerFound {
				// Outer tag
				outerBaseTag := fmt.Sprintf("wg-%s-outer", outerAcc.Name)
				tagCount[outerBaseTag]++
				outerTag := outerBaseTag
				if tagCount[outerBaseTag] > 1 {
					outerTag = fmt.Sprintf("%s-%d", outerBaseTag, tagCount[outerBaseTag])
				}

				// Outer outbound: MTU=1330, direct (no detour), not in selector.
				outerWGOpts, err := buildWGOutboundOptions(outerAcc, 1330, "")
				if err != nil {
					return nil, err
				}
				outbounds = append(outbounds, option.Outbound{
					Type:    C.TypeWireGuard,
					Tag:     outerTag,
					Options: outerWGOpts,
				})

				// Inner outbound: MTU=1280, detour through outer.
				innerWGOpts, err := buildWGOutboundOptions(acc, 1280, outerTag)
				if err != nil {
					return nil, err
				}
				outbounds = append(outbounds, option.Outbound{
					Type:    C.TypeWireGuard,
					Tag:     innerTag,
					Options: innerWGOpts,
				})
			} else {
				// Outer unavailable (disabled), fall back to single WG.
				wgOpts, err := buildWGOutboundOptions(acc, 1280, "")
				if err != nil {
					return nil, err
				}
				outbounds = append(outbounds, option.Outbound{
					Type:    C.TypeWireGuard,
					Tag:     innerTag,
					Options: wgOpts,
				})
			}

			selectorTags = append(selectorTags, innerTag)
		} else {
			// Regular single account.
			baseTag := fmt.Sprintf("wg-%s", acc.Name)
			tagCount[baseTag]++
			tag := baseTag
			if tagCount[baseTag] > 1 {
				tag = fmt.Sprintf("%s-%d", baseTag, tagCount[baseTag])
			}

			wgOpts, err := buildWGOutboundOptions(acc, 1280, "")
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
