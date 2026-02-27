package store

import "time"

type Account struct {
	ID            string    `json:"id"`
	Name          string    `json:"name"`
	PrivateKey    string    `json:"private_key"`
	PublicKey     string    `json:"public_key"`
	PeerPublicKey string    `json:"peer_public_key"`
	Endpoint      string    `json:"endpoint"`
	EndpointPort  uint16    `json:"endpoint_port"`
	IPv4          string    `json:"ipv4"`
	IPv6          string    `json:"ipv6"`
	Reserved      []uint8   `json:"reserved"`
	Token         string    `json:"token"`
	Enabled       bool      `json:"enabled"`
	CreatedAt     time.Time `json:"created_at"`
}

type Settings struct {
	// Proxy listen
	ProxyHost string `json:"proxy_host"`
	SocksPort uint16 `json:"socks_port"`
	HTTPPort  uint16 `json:"http_port"`

	// Proxy auth
	ProxyUser string `json:"proxy_user"`
	ProxyPass string `json:"proxy_pass"`

	// WebUI
	WebAddr string `json:"web_addr"`
	WebUser string `json:"web_user"`
	WebPass string `json:"web_pass"`

	// Rotation
	RotationMode     string `json:"rotation_mode"`
	URLTestURL       string `json:"urltest_url"`
	URLTestInterval  int    `json:"urltest_interval"`
	URLTestTolerance uint16 `json:"urltest_tolerance"`
	RandomInterval   int    `json:"random_interval"`

	// Clash API
	ClashAPIPort   uint16 `json:"clash_api_port"`
	ClashAPISecret string `json:"clash_api_secret"`

	// Update
	UpdateChannel string `json:"update_channel"` // "dev" or "stable"
}

func DefaultSettings() Settings {
	return Settings{
		ProxyHost:        "127.0.0.1",
		SocksPort:        1080,
		HTTPPort:         8080,
		WebAddr:          ":9090",
		WebUser:          "admin",
		WebPass:          "admin",
		RotationMode:     "urltest",
		URLTestURL:       "https://www.gstatic.com/generate_204",
		URLTestInterval:  300,
		URLTestTolerance: 50,
		RandomInterval:   30,
		ClashAPIPort:     9097,
		ClashAPISecret:   "",
		UpdateChannel:    "dev",
	}
}
