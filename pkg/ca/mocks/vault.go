package mocks

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net"
	"strings"
	"testing"

	"github.com/lamassuiot/enroller/pkg/ca/secrets"

	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/builtin/logical/pki"
	"github.com/hashicorp/vault/http"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/hashicorp/vault/vault"
)

type vaultSecretsMock struct {
	client *api.Client
}

func NewVaultSecretsMock(t *testing.T) (secrets.Secrets, net.Listener, error) {
	t.Helper()

	coreConfig := &vault.CoreConfig{
		LogicalBackends: map[string]logical.Factory{
			"pki": pki.Factory,
		},
	}

	core, keyShares, rootToken := vault.TestCoreUnsealedWithConfig(t, coreConfig)
	_ = keyShares

	ln, addr := http.TestServer(t, core)

	conf := api.DefaultConfig()
	conf.Address = strings.ReplaceAll(conf.Address, "https://127.0.0.1:8200", addr)

	client, err := api.NewClient(conf)
	if err != nil {
		return nil, nil, err
	}
	client.SetToken(rootToken)

	//Mount CA PKI Backend
	_, err = client.Logical().Write("sys/mounts/Lamassu-Root-CA1-RSA4096", map[string]interface{}{
		"type": "pki",
		"config": map[string]interface{}{
			"max_lease_ttl": "262800h",
		},
	})
	if err != nil {
		return nil, nil, err
	}

	//Setup CA Role
	_, err = client.Logical().Write("Lamassu-Root-CA1-RSA4096/roles/enroller", map[string]interface{}{
		"allow_any_name": true,
		"max_ttl":        "262800h",
		"key_type":       "any",
	})
	if err != nil {
		return nil, nil, err
	}

	//Setup CA internal root certificate
	_, err = client.Logical().Write("Lamassu-Root-CA1-RSA4096/root/generate/internal", map[string]interface{}{
		"common_name":  "LKS Next Root CA 1",
		"key_type":     "rsa",
		"key_bits":     "4096",
		"organization": "LKS Next S. Coop",
		"country":      "ES",
		"ttl":          "262800h",
		"province":     "Gipuzkoa",
		"locality":     "Arrasate",
	})
	if err != nil {
		return nil, nil, err
	}

	return &vaultSecretsMock{client: client}, ln, nil
}

func (vm *vaultSecretsMock) GetCAs() (secrets.CAs, error) {
	resp, err := vm.client.Sys().ListMounts()
	if err != nil {
		return secrets.CAs{}, err
	}
	var CAs []secrets.CA
	for mount, mountOutput := range resp {
		if mountOutput.Type == "pki" {
			CAs = append(CAs, secrets.CA{Name: strings.TrimSuffix(mount, "/")})
		}
	}
	return secrets.CAs{CAs: CAs}, nil
}

func (vm *vaultSecretsMock) GetCAInfo(CA string) (secrets.CAInfo, error) {
	caPath := CA + "/cert/ca"
	resp, err := vm.client.Logical().Read(caPath)
	if resp == nil {
		return secrets.CAInfo{}, nil
	}
	if err != nil {
		return secrets.CAInfo{}, err
	}
	pemBlock, _ := pem.Decode([]byte(resp.Data["certificate"].(string)))
	if pemBlock == nil {
		return secrets.CAInfo{}, errors.New("Cannot find the next PEM formatted block")
	}
	if pemBlock.Type != "CERTIFICATE" || len(pemBlock.Headers) != 0 {
		return secrets.CAInfo{}, errors.New("Unmatched type of headers")
	}
	caCert, err := x509.ParseCertificate(pemBlock.Bytes)
	if err != nil {
		return secrets.CAInfo{}, err
	}
	key := caCert.PublicKeyAlgorithm.String()
	var keyBits int
	switch key {
	case "RSA":
		keyBits = caCert.PublicKey.(*rsa.PublicKey).N.BitLen()
	case "ECDSA":
		keyBits = caCert.PublicKey.(*ecdsa.PublicKey).Params().BitSize
	}

	CAInfo := secrets.CAInfo{
		C:       strings.Join(caCert.Subject.Country, " "),
		L:       strings.Join(caCert.Subject.Locality, " "),
		O:       strings.Join(caCert.Subject.Organization, " "),
		ST:      strings.Join(caCert.Subject.Province, " "),
		CN:      caCert.Subject.CommonName,
		KeyType: key,
		KeyBits: keyBits,
	}

	return CAInfo, nil
}

func (vm *vaultSecretsMock) DeleteCA(CA string) error {
	deletePath := CA + "/root"
	_, err := vm.client.Logical().Delete(deletePath)
	if err != nil {
		return err
	}
	return nil
}
