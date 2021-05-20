package vault

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/lamassuiot/lamassu-ca/pkg/secrets"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"

	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/helper/namespace"
	"github.com/hashicorp/vault/vault"
)

type vaultSecrets struct {
	client   *api.Client
	roleID   string
	secretID string
	logger   log.Logger
}

func NewVaultSecrets(address string, roleID string, secretID string, CA string, logger log.Logger) (*vaultSecrets, error) {
	conf := api.DefaultConfig()
	conf.Address = strings.ReplaceAll(conf.Address, "https://127.0.0.1:8200", address)
	tlsConf := &api.TLSConfig{CACert: CA}
	conf.ConfigureTLS(tlsConf)
	client, err := api.NewClient(conf)
	if err != nil {
		level.Error(logger).Log("err", err, "msg", "Could not create Vault API client")
		return nil, err
	}

	err = Login(client, roleID, secretID)
	if err != nil {
		level.Error(logger).Log("err", err, "msg", "Could not login into Vault")
		return nil, err
	}
	return &vaultSecrets{client: client, roleID: roleID, secretID: secretID, logger: logger}, nil
}

func Login(client *api.Client, roleID string, secretID string) error {
	loginPath := "auth/approle/login"
	options := map[string]interface{}{
		"role_id":   roleID,
		"secret_id": secretID,
	}
	resp, err := client.Logical().Write(loginPath, options)
	if err != nil {
		return err
	}
	client.SetToken(resp.Auth.ClientToken)
	return nil
}

func (vs *vaultSecrets) GetCAs() (secrets.CAs, error) {
	resp, err := vs.client.Sys().ListMounts()
	if err != nil {
		level.Error(vs.logger).Log("err", err, "msg", "Could not obtain list of Vault mounts")
		return secrets.CAs{}, err
	}
	var CAs secrets.CAs
	for mount, mountOutput := range resp {
		if mountOutput.Type == "pki" {
			caName := strings.TrimSuffix(mount, "/")
			caPath := caName + "/cert/ca"

			resp, err := vs.client.Logical().Read(caPath)
			if err != nil {
				level.Warn(vs.logger).Log("err", err, "msg", "Could not read "+caName+" certificate from Vault")
				continue
			}
			if resp == nil {
				level.Warn(vs.logger).Log("Mount path " + mount + " does not have a root CA")
				continue
			}
			cert, err := DecodeCert(caName, []byte(resp.Data["certificate"].(string)))
			if err != nil {
				err = errors.New("Cannot decode cert. Perhaps it is malphormed")
				level.Warn(vs.logger).Log("err", err)
				continue
			}

			_, keyType, keyBits := getPublicKeyInfo(cert)

			CAs.CAs = append(CAs.CAs, secrets.CA{
				SerialNumber: cert.Subject.SerialNumber,
				CaName:       caName,
				C:            strings.Join(cert.Subject.Country, " "),
				ST:           strings.Join(cert.Subject.Province, " "),
				L:            strings.Join(cert.Subject.Locality, " "),
				O:            strings.Join(cert.Subject.Organization, " "),
				OU:           strings.Join(cert.Subject.OrganizationalUnit, " "),
				CN:           cert.Subject.CommonName,
				KeyType:      keyType,
				KeyBits:      keyBits,
			})
		}
	}
	level.Info(vs.logger).Log("msg", strconv.Itoa(len(CAs.CAs))+" obtained from Vault mounts")
	return CAs, nil
}

func (vs *vaultSecrets) GetCACrt(caName string) (secrets.CACrt, error) {
	caPath := caName + "/cert/ca"
	resp, err := vs.client.Logical().Read(caPath)
	if err != nil {
		level.Error(vs.logger).Log("err", err, "msg", "Could not read "+caName+" certificate from Vault")
		return secrets.CACrt{}, err
	}
	cert, err := DecodeCert(caName, []byte(resp.Data["certificate"].(string)))
	if err != nil {
		level.Error(vs.logger).Log("err", err, "msg", "Could not decode certificate: perhaps it is malformed")
		return secrets.CACrt{}, err
	}
	pubKey, _, _ := getPublicKeyInfo(cert)
	return secrets.CACrt{CRT: resp.Data["certificate"].(string), PublicKey: pubKey}, nil
}

func (vs *vaultSecrets) CreateCA(CAName string, ca secrets.CA) error {
	mountInput := api.MountInput{Type: "pki", Description: ""}
	err := vs.client.Sys().Mount(CAName, &mountInput)
	if err != nil {
		level.Error(vs.logger).Log("err", err, "msg", "Could not create a new pki mount point on Vault")
		return err
	}

	err = vs.client.Sys().PutPolicy(CAName+"-policy", "path \""+CAName+"*\" {\n capabilities=[\"create\", \"read\", \"update\", \"delete\", \"list\", \"sudo\"]\n}")
	if err != nil {
		level.Error(vs.logger).Log("err", err, "msg", "Could not create a new policy for "+CAName+" CA on Vault")
		return err
	}

	enrollerPolicy, err := vs.client.Sys().GetPolicy("enroller-ca-policy")
	if err != nil {
		level.Error(vs.logger).Log("err", err, "msg", "Error while modifying enroller-ca-policy policy on Vault")
		return err
	}

	policy, err := vault.ParseACLPolicy(namespace.RootNamespace, enrollerPolicy)
	if err != nil {
		level.Error(vs.logger).Log("err", err, "msg", "Error while parsing enroller-ca-policy policy")
		return err
	}

	rootPathRules := vault.PathRules{Path: CAName, Capabilities: []string{"create", "read", "update", "delete", "list", "sudo"}, IsPrefix: true}
	caPathRules := vault.PathRules{Path: CAName + "/cert/ca", Capabilities: []string{"create", "read", "update", "delete", "list", "sudo"}}
	enrollerPathRules := vault.PathRules{Path: CAName + "/roles/enroller", Capabilities: []string{"create", "read", "update", "delete", "list", "sudo"}}
	policy.Paths = append(policy.Paths, &rootPathRules, &caPathRules, &enrollerPathRules)

	newPolicy := PolicyToString(*policy)

	err = vs.client.Sys().PutPolicy("enroller-ca-policy", newPolicy)
	if err != nil {
		level.Error(vs.logger).Log("err", err, "msg", "Error while modifying enroller-ca-policy policy on Vault")
		return err
	}

	_, err = vs.client.Logical().Write(CAName+"/roles/enroller", map[string]interface{}{
		"allow_any_name": true,
		"ttl":            "175200h", //30Años
		"max_ttl":        "262800h", //20Años
		"key_type":       "any",
	})
	if err != nil {
		level.Error(vs.logger).Log("err", err, "msg", "Could not create a new role for "+CAName+" CA on Vault")
		return err
	}

	options := map[string]interface{}{
		"common_name":  ca.C,
		"key_type":     ca.KeyType,
		"key_bits":     ca.KeyBits,
		"organization": ca.O,
		"country":      ca.OU,
		"province":     ca.ST,
		"locality":     ca.L,
		"ttl":          "262800h",
	}
	_, err = vs.client.Logical().Write(CAName+"/root/generate/internal", options)
	if err != nil {
		level.Error(vs.logger).Log("err", err, "msg", "Could not intialize the root CA certificate for "+CAName+" CA on Vault")
		return err
	}
	return nil
}

func (vs *vaultSecrets) DeleteCA(ca string) error {
	deletePath := ca + "/root"
	_, err := vs.client.Logical().Delete(deletePath)
	if err != nil {
		level.Error(vs.logger).Log("err", err, "msg", "Could not delete "+ca+" certificate from Vault")
		return err
	}
	return nil
}

func DecodeCert(caName string, cert []byte) (x509.Certificate, error) {
	pemBlock, _ := pem.Decode(cert)
	if pemBlock == nil {
		err := errors.New("Cannot find the next formatted block")
		// level.Error(vs.logger).Log("err", err)
		return x509.Certificate{}, err
	}
	if pemBlock.Type != "CERTIFICATE" || len(pemBlock.Headers) != 0 {
		err := errors.New("Unmatched type of headers")
		// level.Error(vs.logger).Log("err", err)
		return x509.Certificate{}, err
	}
	caCert, err := x509.ParseCertificate(pemBlock.Bytes)
	if err != nil {
		// level.Error(vs.logger).Log("err", err, "msg", "Could not parse "+caName+" CA certificate")
		return x509.Certificate{}, err
	}
	return *caCert, nil
}

func getPublicKeyInfo(cert x509.Certificate) (string, string, int) {
	key := cert.PublicKeyAlgorithm.String()
	var keyBits int
	switch key {
	case "RSA":
		keyBits = cert.PublicKey.(*rsa.PublicKey).N.BitLen()
	case "ECDSA":
		keyBits = cert.PublicKey.(*ecdsa.PublicKey).Params().BitSize
	}
	publicKeyDer, _ := x509.MarshalPKIXPublicKey(cert.PublicKey)
	fmt.Println(publicKeyDer)
	publicKeyBlock := pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyDer,
	}
	publicKeyPem := string(pem.EncodeToMemory(&publicKeyBlock))
	fmt.Println(publicKeyPem)

	return publicKeyPem, key, keyBits
}

func PolicyToString(policy vault.Policy) string {
	var policyString string = ""
	for i, p := range policy.Paths {
		pathPrefix := ""
		if p.IsPrefix {
			pathPrefix = "*"
		}
		policyString = policyString + "path \"" + p.Path + pathPrefix + "\" {\n capabilities=["
		for j, c := range p.Capabilities {
			policyString = policyString + "\"" + c + "\""
			if j < len(p.Capabilities)-1 {
				policyString = policyString + ","
			}
		}
		policyString = policyString + "]\n}"
		if i < len(policy.Paths)-1 {
			policyString = policyString + "\n"
		}
	}
	return policyString
}
