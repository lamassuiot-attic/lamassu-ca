package vault

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"strconv"
	"strings"
	"time"

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

func (vs *vaultSecrets) GetCA(caName string) (secrets.Cert, error) {
	resp, err := vs.client.Logical().Read(caName + "/cert/ca")
	if err != nil {
		level.Warn(vs.logger).Log("err", err, "msg", "Could not read "+caName+" certificate from Vault")
		return secrets.Cert{}, err
	}
	if resp == nil {
		level.Warn(vs.logger).Log("Mount path for PKI " + caName + " does not have a root CA")
		return secrets.Cert{}, err

	}
	cert, err := DecodeCert(caName, []byte(resp.Data["certificate"].(string)))
	if err != nil {
		err = errors.New("Cannot decode cert. Perhaps it is malphormed")
		level.Warn(vs.logger).Log("err", err)
		return secrets.Cert{}, err
	}
	pubKey, keyType, keyBits, keyStrength := getPublicKeyInfo(cert)
	hasExpired := cert.NotAfter.Before(time.Now())
	status := "issued"
	if hasExpired {
		status = "expired"
	}

	if !vs.hasEnrollerRole(caName) {
		status = "revoked"
	}

	return secrets.Cert{
		SerialNumber: insertNth(toHexInt(cert.SerialNumber), 2),
		Status:       status,
		CRT:          resp.Data["certificate"].(string),
		CaName:       caName,
		PublicKey:    pubKey,
		C:            strings.Join(cert.Subject.Country, " "),
		ST:           strings.Join(cert.Subject.Province, " "),
		L:            strings.Join(cert.Subject.Locality, " "),
		O:            strings.Join(cert.Subject.Organization, " "),
		OU:           strings.Join(cert.Subject.OrganizationalUnit, " "),
		CN:           cert.Subject.CommonName,
		ValidFrom:    cert.NotBefore.String(),
		ValidTO:      cert.NotAfter.String(),
		KeyType:      keyType,
		KeyBits:      keyBits,
		KeyStrength:  keyStrength,
	}, nil
}

func (vs *vaultSecrets) GetCAs(caType secrets.CAType) (secrets.Certs, error) {
	resp, err := vs.client.Sys().ListMounts()
	if err != nil {
		level.Error(vs.logger).Log("err", err, "msg", "Could not obtain list of Vault mounts")
		return secrets.Certs{}, err
	}
	var CAs secrets.Certs
	lamassuSytemCARootCert, err := vs.getLamassuSystemCARootCert()
	if err != nil {
		level.Error(vs.logger).Log("err", err, "msg", "Could not obtain Lamassu System CA Root Cert")
		return secrets.Certs{}, err
	}
	for mount, mountOutput := range resp {
		if mountOutput.Type == "pki" {
			caName := strings.TrimSuffix(mount, "/")
			cert, err := vs.GetCA(caName)
			if err != nil {
				level.Error(vs.logger).Log("err", err, "msg", "Could not get CA cert for "+caName)
				continue
			}
			switch caType {
			case secrets.AllCAs:
				CAs.Certs = append(CAs.Certs, cert)
			case secrets.SystemCAs:
				x509Cert, _ := DecodeCert(caName, []byte(cert.CRT))
				isLamassuSystemCAResult := isLamassuSystemCA(lamassuSytemCARootCert, x509Cert)
				if isLamassuSystemCAResult {
					CAs.Certs = append(CAs.Certs, cert)
				}
			case secrets.OperationsCAs:
				x509Cert, _ := DecodeCert(caName, []byte(cert.CRT))
				if !isLamassuSystemCA(lamassuSytemCARootCert, x509Cert) {
					CAs.Certs = append(CAs.Certs, cert)
				}
			}
		}
	}
	level.Info(vs.logger).Log("msg", strconv.Itoa(len(CAs.Certs))+" obtained from Vault mounts")
	return CAs, nil
}

func (vs *vaultSecrets) CreateCA(CAName string, ca secrets.Cert) error {
	err := initPkiSecret(vs, CAName, ca.CaTTL)
	if err != nil {
		return err
	}
	options := map[string]interface{}{
		"key_type":          ca.KeyType,
		"key_bits":          ca.KeyBits,
		"country":           ca.C,
		"province":          ca.ST,
		"locality":          ca.L,
		"organization":      ca.O,
		"organization_unit": ca.OU,
		"common_name":       ca.CN,
		"ttl":               strconv.Itoa(ca.CaTTL) + "h",
	}
	_, err = vs.client.Logical().Write(CAName+"/root/generate/internal", options)
	if err != nil {
		level.Error(vs.logger).Log("err", err, "msg", "Could not intialize the root CA certificate for "+CAName+" CA on Vault")
		return err
	}
	return nil
}

func (vs *vaultSecrets) ImportCA(CAName string, caImport secrets.CAImport) error {
	err := initPkiSecret(vs, CAName, caImport.TTL)
	if err != nil {
		return err
	}
	options := map[string]interface{}{
		"pem_bundle": caImport.PEMBundle,
	}
	vs.client.Logical().Write(CAName+"/config/ca", options)
	return nil
}

func initPkiSecret(vs *vaultSecrets, CAName string, enrollerTTL int) error {
	mountInput := api.MountInput{Type: "pki", Description: ""}
	err := vs.client.Sys().Mount(CAName, &mountInput)
	if err != nil {
		level.Error(vs.logger).Log("err", err, "msg", "Could not create a new pki mount point on Vaul.t")
		if strings.Contains(err.Error(), "path is already in use") {
			return errors.New("Could no create CA \"" + CAName + "\". Already exists")
		} else {
			return err
		}
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
	//caPathRules := vault.PathRules{Path: CAName + "/cert/ca", Capabilities: []string{"create", "read", "update", "delete", "list", "sudo"}}
	//enrollerPathRules := vault.PathRules{Path: CAName + "/roles/enroller", Capabilities: []string{"create", "read", "update", "delete", "list", "sudo"}}
	//policy.Paths = append(policy.Paths, &rootPathRules, &caPathRules, &enrollerPathRules)
	policy.Paths = append(policy.Paths, &rootPathRules)

	newPolicy := PolicyToString(*policy)

	err = vs.client.Sys().PutPolicy("enroller-ca-policy", newPolicy)
	if err != nil {
		level.Error(vs.logger).Log("err", err, "msg", "Error while modifying enroller-ca-policy policy on Vault")
		return err
	}

	_, err = vs.client.Logical().Write(CAName+"/roles/enroller", map[string]interface{}{
		"allow_any_name": true,
		"ttl":            strconv.Itoa(enrollerTTL) + "h",
		"max_ttl":        strconv.Itoa(enrollerTTL) + "h",
		"key_type":       "any",
	})
	if err != nil {
		level.Error(vs.logger).Log("err", err, "msg", "Could not create a new role for "+CAName+" CA on Vault")
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
	_, err = vs.client.Logical().Delete(ca + "/roles/enroller")
	if err != nil {
		level.Error(vs.logger).Log("err", err, "msg", "Could not delete enroller role from CA "+ca)
		return err
	}
	return nil
}

func (vs *vaultSecrets) GetIssuedCerts(caName string) (secrets.Certs, error) {
	var Certs secrets.Certs

	if caName == "" {
		cas, err := vs.GetCAs(secrets.AllCAs)
		if err != nil {
			level.Error(vs.logger).Log("err", err, "msg", "Could not get CAs from Vault")
			return secrets.Certs{}, err
		}
		for _, cert := range cas.Certs {
			if cert.CaName != "" {
				certsSubset, err := vs.GetIssuedCerts(cert.CaName)
				if err != nil {
					level.Error(vs.logger).Log("err", err, "msg", "Error while getting issued cert subset for CA "+cert.CaName)
					continue
				}
				Certs.Certs = append(Certs.Certs, certsSubset.Certs...)
			}
		}
	} else {
		getCertsPath := caName + "/certs"
		resp, err := vs.client.Logical().List(getCertsPath)
		if err != nil {
			level.Error(vs.logger).Log("err", err, "msg", "Could not read "+caName+" mount path from Vault")
			return secrets.Certs{}, err
		}

		caCert, err := vs.GetCA(caName)
		if err != nil {
			level.Error(vs.logger).Log("err", err, "msg", "Could not get CA cert for "+caName)
			return secrets.Certs{}, err
		}

		for _, elem := range resp.Data["keys"].([]interface{}) {
			certSerialID := elem.(string)
			if caCert.SerialNumber == certSerialID {
				continue
			}
			certResponse, err := vs.client.Logical().Read(caName + "/cert/" + certSerialID)
			if err != nil {
				level.Error(vs.logger).Log("err", err, "msg", "Could not read certificate "+certSerialID+" from CA "+caName)
				continue
			}
			cert, err := DecodeCert(caName, []byte(certResponse.Data["certificate"].(string)))
			if err != nil {
				err = errors.New("Cannot decode cert " + certSerialID + ". Perhaps it is malphormed")
				level.Warn(vs.logger).Log("err", err)
				continue
			}

			pubKey, keyType, keyBits, keyStrength := getPublicKeyInfo(cert)
			hasExpired := cert.NotAfter.Before(time.Now())
			status := "issued"
			if hasExpired {
				status = "expired"
			}
			revocation_time, err := certResponse.Data["revocation_time"].(json.Number).Int64()
			if err != nil {
				err = errors.New("revocation_time not an INT for cert " + certSerialID + ".")
				level.Warn(vs.logger).Log("err", err)
				continue
			}
			if revocation_time != 0 {
				status = "revoked"
			}

			Certs.Certs = append(Certs.Certs, secrets.Cert{
				SerialNumber: insertNth(toHexInt(cert.SerialNumber), 2),
				Status:       status,
				CRT:          certResponse.Data["certificate"].(string),
				CaName:       caName,
				PublicKey:    pubKey,
				C:            strings.Join(cert.Subject.Country, " "),
				ST:           strings.Join(cert.Subject.Province, " "),
				L:            strings.Join(cert.Subject.Locality, " "),
				O:            strings.Join(cert.Subject.Organization, " "),
				OU:           strings.Join(cert.Subject.OrganizationalUnit, " "),
				ValidFrom:    cert.NotBefore.String(),
				ValidTO:      cert.NotAfter.String(),
				CN:           cert.Subject.CommonName,
				KeyType:      keyType,
				KeyBits:      keyBits,
				KeyStrength:  keyStrength,
			})
		}
	}
	return Certs, nil

}

func (vs *vaultSecrets) DeleteCert(caName string, serialNumber string) error {
	options := map[string]interface{}{
		"serial_number": serialNumber,
	}
	_, err := vs.client.Logical().Write(caName+"/revoke", options)
	if err != nil {
		level.Error(vs.logger).Log("err", err, "msg", "Could not revoke cert with serial number "+serialNumber+" from CA "+caName)
		return err
	}
	return nil
}

func insertNth(s string, n int) string {
	var buffer bytes.Buffer
	var n_1 = n - 1
	var l_1 = len(s) - 1
	for i, rune := range s {
		buffer.WriteRune(rune)
		if i%n == n_1 && i != l_1 {
			buffer.WriteRune('-')
		}
	}
	return buffer.String()
}

func toHexInt(n *big.Int) string {
	return fmt.Sprintf("%x", n) // or %X or upper case
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

func (vs *vaultSecrets) getLamassuSystemCARootCert() (x509.Certificate, error) {
	secretCert, err := vs.GetCA("Lamassu-System-CA")
	if err != nil {
		// level.Error(vs.logger).Log("err", err, "msg", "Could not parse "+caName+" CA certificate")
		return x509.Certificate{}, err
	}
	cert, err := DecodeCert("Lamassu-System-CA", []byte(secretCert.CRT))
	return cert, err
}

func (vs *vaultSecrets) hasEnrollerRole(caName string) bool {
	data, _ := vs.client.Logical().Read(caName + "/roles/enroller")
	if data == nil {
		return false
	} else {
		return true
	}
}

func isLamassuSystemCA(lamassuSystemRootCaCert x509.Certificate, cert x509.Certificate) bool {
	roots := x509.NewCertPool()
	roots.AddCert(&lamassuSystemRootCaCert)

	opts := x509.VerifyOptions{
		Roots: roots,
	}

	if _, err := cert.Verify(opts); err != nil {
		return false
	} else {
		return true
	}
}

func getPublicKeyInfo(cert x509.Certificate) (string, string, int, string) {
	key := cert.PublicKeyAlgorithm.String()
	var keyBits int
	switch key {
	case "RSA":
		keyBits = cert.PublicKey.(*rsa.PublicKey).N.BitLen()
	case "ECDSA":
		keyBits = cert.PublicKey.(*ecdsa.PublicKey).Params().BitSize
	}
	publicKeyDer, _ := x509.MarshalPKIXPublicKey(cert.PublicKey)
	publicKeyBlock := pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyDer,
	}
	publicKeyPem := string(pem.EncodeToMemory(&publicKeyBlock))

	var keyStrength string = "unknown"
	switch key {
	case "RSA":
		if keyBits <= 2048 {
			keyStrength = "low"
		} else if keyBits > 2048 && keyBits <= 3072 {
			keyStrength = "medium"
		} else {
			keyStrength = "high"
		}
	case "ECDSA":
		if keyBits <= 128 {
			keyStrength = "low"
		} else if keyBits > 128 && keyBits <= 256 {
			keyStrength = "medium"
		} else {
			keyStrength = "high"
		}
	}

	return publicKeyPem, key, keyBits, keyStrength
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
