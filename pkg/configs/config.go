package configs

import "github.com/kelseyhightower/envconfig"

type Config struct {
	Port     string `required:"true" split_words:"true"`
	Protocol string `required:"true" split_words:"true"`

	OcspUrl string `required:"true" split_words:"true"`

	OidcWellKnownUrl string `required:"true" split_words:"true"`
	OidcCA           string `split_words:"true"`

	VaultAddress  string `required:"true" split_words:"true"`
	VaultRoleID   string `required:"true" split_words:"true"`
	VaultSecretID string `required:"true" split_words:"true"`
	VaultCA       string `split_words:"true"`

	VaultPkiCaPath string `required:"true" split_words:"true"`

	CertFile string `split_words:"true"`
	KeyFile  string `split_words:"true"`
}

func NewConfig(prefix string) (Config, error) {
	var cfg Config
	err := envconfig.Process(prefix, &cfg)
	if err != nil {
		return Config{}, err
	}
	return cfg, nil
}
