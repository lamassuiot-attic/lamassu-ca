package configs

import (
	"encoding/json"
	"io/ioutil"
)

// ServerConfig  contains the EST server configuration.
type ServerConfig struct {
	CA                  *CAConfig     `json:"ca,omitempty"`
	TLS                 *tlsConfig    `json:"tls,omitempty"`
	AllowedHosts        []string      `json:"allowed_hosts,omitempty"`
	HealthCheckPassword string        `json:"healthcheck_password"`
	RateLimit           int           `json:"rate_limit"`
	Timeout             int           `json:"timeout"`
	Logfile             string        `json:"log_file"`
	Consul              *consulConfig `json:"consul"`
	Proxy               *proxyConfig  `json:"proxy"`
}

// consulConfig  contains the consul configuration.
type consulConfig struct {
	ConsulProtocol string
	ConsulHost     string
	ConsulPort     string
	ConsulCA       string
}

// proxyConfig contains proxy configuration.
type proxyConfig struct {
	roxyHost  string
	ProxyPort string
	ProxyCA   string
}

// CAConfig CAConfig contains the mock CA configuration.
type CAConfig struct {
	Certs string `json:"certificates"`
	Key   string `json:"private_key"`
}

// tlsConfig contains the server's TLS configuration.
type tlsConfig struct {
	ListenAddr string   `json:"listen_address"`
	Certs      string   `json:"certificates"`
	Key        string   `json:"private_key"`
	ClientCAs  []string `json:"client_cas,omitempty"`
}

// ConfigFromFile returns a new EST server configuration from a JSON-encoded configuration file.
func ConfigFromFile(filename string) (*ServerConfig, error) {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	var cfg ServerConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}

	return &cfg, nil
}
