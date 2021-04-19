package configs

import "github.com/kelseyhightower/envconfig"

type Config struct {
	Port string

	EnrollerUIHost     string
	EnrollerUIPort     string
	EnrollerUIProtocol string

	ConsulProtocol string
	ConsulHost     string
	ConsulPort     string
	ConsulCA       string

	KeycloakHostname string
	KeycloakPort     string
	KeycloakProtocol string
	KeycloakRealm    string
	KeycloakCA       string

	VaultAddress  string
	VaultRoleID   string
	VaultSecretID string
	VaultCA       string

	CertFile string
	KeyFile  string
}

func NewConfig(prefix string) (Config, error) {
	var cfg Config
	err := envconfig.Process(prefix, &cfg)
	if err != nil {
		return Config{}, err
	}
	return cfg, nil
}
