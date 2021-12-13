package vault

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"strconv"
	"strings"
	"time"

	"github.com/lamassuiot/lamassu-ca/pkg/secrets"
	"github.com/opentracing/opentracing-go"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"

	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/vault"
)

type vaultSecrets struct {
	client   *api.Client
	roleID   string
	secretID string
	pkiPath  string
	logger   log.Logger
	ocspUrl  string
}

func NewVaultSecrets(address string, pkiPath string, roleID string, secretID string, CA string, ocspUrl string, logger log.Logger) (*vaultSecrets, error) {
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
	return &vaultSecrets{
		client:   client,
		pkiPath:  pkiPath,
		roleID:   roleID,
		secretID: secretID,
		ocspUrl:  ocspUrl,
		logger:   logger,
	}, nil
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

func (vs *vaultSecrets) SignCertificate(caName string, csr *x509.CertificateRequest) ([]byte, error) {
	csrBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr.Raw})
	options := map[string]interface{}{
		"csr":         string(csrBytes),
		"common_name": csr.Subject.CommonName,
	}
	data, err := vs.client.Logical().Write(vs.pkiPath+caName+"/sign-verbatim/enroller", options)
	if err != nil {
		return nil, err
	}
	certData := data.Data["certificate"]
	certPEMBlock, _ := pem.Decode([]byte(certData.(string)))
	if certPEMBlock == nil || certPEMBlock.Type != "CERTIFICATE" {
		err = errors.New("failed to decode PEM block containing certificate")
		return nil, err
	}

	return certPEMBlock.Bytes, nil
}

func (vs *vaultSecrets) GetCA(ctx context.Context, caName string) (secrets.Cert, error) {
	// var span jaeger.Span
	// ctx.Value(&span)

	span, _ := opentracing.StartSpanFromContext(ctx, "lamassu-ca-api: vault-api GET /"+vs.pkiPath+caName+"/cert/ca")
	resp, err := vs.client.Logical().Read(vs.pkiPath + caName + "/cert/ca")
	span.Finish()

	if err != nil {
		level.Warn(vs.logger).Log("err", err, "msg", "Could not read "+caName+" certificate from Vault")
		return secrets.Cert{}, err
	}
	if resp == nil {
		level.Warn(vs.logger).Log("Mount path for PKI " + caName + " does not have a root CA")
		return secrets.Cert{}, err
	}

	certBytes := []byte(resp.Data["certificate"].(string))
	cert, err := DecodeCert(certBytes)
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
		Name:         caName,
		CertContent: secrets.CertContent{
			CerificateBase64: base64.StdEncoding.EncodeToString([]byte(resp.Data["certificate"].(string))),
			PublicKeyBase64:  base64.StdEncoding.EncodeToString([]byte(pubKey)),
		},
		Subject: secrets.Subject{
			C:  strings.Join(cert.Subject.Country, " "),
			ST: strings.Join(cert.Subject.Province, " "),
			L:  strings.Join(cert.Subject.Locality, " "),
			O:  strings.Join(cert.Subject.Organization, " "),
			OU: strings.Join(cert.Subject.OrganizationalUnit, " "),
			CN: cert.Subject.CommonName,
		},
		KeyMetadata: secrets.KeyInfo{
			KeyType:     keyType,
			KeyBits:     keyBits,
			KeyStrength: keyStrength,
		},
		ValidFrom: cert.NotBefore.String(),
		ValidTo:   cert.NotAfter.String(),
	}, nil
}

func (vs *vaultSecrets) GetCAs(ctx context.Context) (secrets.Certs, error) {
	resp, err := vs.client.Sys().ListMounts()
	if err != nil {
		level.Error(vs.logger).Log("err", err, "msg", "Could not obtain list of Vault mounts")
		return secrets.Certs{}, err
	}
	var CAs secrets.Certs

	for mount, mountOutput := range resp {
		if mountOutput.Type == "pki" && strings.HasPrefix(mount, vs.pkiPath) {
			caName := strings.TrimSuffix(mount, "/")
			caName = strings.TrimPrefix(caName, vs.pkiPath)
			cert, err := vs.GetCA(ctx, caName)
			if err != nil {
				level.Error(vs.logger).Log("err", err, "msg", "Could not get CA cert for "+caName)
				continue
			}
			CAs.Certs = append(CAs.Certs, cert)
		}
	}
	level.Info(vs.logger).Log("msg", strconv.Itoa(len(CAs.Certs))+" obtained from Vault mounts")
	return CAs, nil
}

func (vs *vaultSecrets) CreateCA(CAName string, ca secrets.Cert) error {
	err := initPkiSecret(vs, CAName, ca.EnrollerTTL)
	if err != nil {
		return err
	}

	tuneOptions := map[string]interface{}{
		"max_lease_ttl": strconv.Itoa(ca.CaTTL) + "h",
	}

	_, err = vs.client.Logical().Write("sys/mounts/"+vs.pkiPath+CAName+"/tune", tuneOptions)
	if err != nil {
		level.Error(vs.logger).Log("err", err, "msg", "Could not tune CA "+CAName)
		return err
	}

	options := map[string]interface{}{
		"key_type":          ca.KeyMetadata.KeyType,
		"key_bits":          ca.KeyMetadata.KeyBits,
		"country":           ca.Subject.C,
		"province":          ca.Subject.ST,
		"locality":          ca.Subject.L,
		"organization":      ca.Subject.O,
		"organization_unit": ca.Subject.OU,
		"common_name":       ca.Subject.CN,
		"ttl":               strconv.Itoa(ca.CaTTL) + "h",
	}
	_, err = vs.client.Logical().Write(vs.pkiPath+CAName+"/root/generate/internal", options)
	if err != nil {
		level.Error(vs.logger).Log("err", err, "msg", "Could not intialize the root CA certificate for "+CAName+" CA on Vault")
		return err
	}
	return nil
}

func (vs *vaultSecrets) ImportCA(CAName string, caImport secrets.CAImport) error {
	fmt.Println(caImport.PEMBundle)
	err := initPkiSecret(vs, CAName, caImport.TTL)
	if err != nil {
		return err
	}
	options := map[string]interface{}{
		"pem_bundle": caImport.PEMBundle,
	}
	_, err = vs.client.Logical().Write(vs.pkiPath+CAName+"/config/ca", options)
	return nil
}

func initPkiSecret(vs *vaultSecrets, CAName string, enrollerTTL int) error {
	mountInput := api.MountInput{Type: "pki", Description: ""}
	err := vs.client.Sys().Mount(vs.pkiPath+CAName, &mountInput)
	if err != nil {
		level.Error(vs.logger).Log("err", err, "msg", "Could not create a new pki mount point on Vaul.t")
		if strings.Contains(err.Error(), "path is already in use") {
			return errors.New("Could no create CA \"" + CAName + "\". Already exists")
		} else {
			return err
		}
	}

	// err = vs.client.Sys().PutPolicy(CAName+"-policy", "path \""+CAName+"*\" {\n capabilities=[\"create\", \"read\", \"update\", \"delete\", \"list\", \"sudo\"]\n}")
	// if err != nil {
	// 	level.Error(vs.logger).Log("err", err, "msg", "Could not create a new policy for "+CAName+" CA on Vault")
	// 	return err
	// }

	// enrollerPolicy, err := vs.client.Sys().GetPolicy("enroller-ca-policy")
	// if err != nil {
	// 	level.Error(vs.logger).Log("err", err, "msg", "Error while modifying enroller-ca-policy policy on Vault")
	// 	return err
	// }

	// policy, err := vault.ParseACLPolicy(namespace.RootNamespace, enrollerPolicy)
	// if err != nil {
	// 	level.Error(vs.logger).Log("err", err, "msg", "Error while parsing enroller-ca-policy policy")
	// 	return err
	// }

	// rootPathRules := vault.PathRules{Path: CAName, Capabilities: []string{"create", "read", "update", "delete", "list", "sudo"}, IsPrefix: true}
	// //caPathRules := vault.PathRules{Path: CAName + "/cert/ca", Capabilities: []string{"create", "read", "update", "delete", "list", "sudo"}}
	// //enrollerPathRules := vault.PathRules{Path: CAName + "/roles/enroller", Capabilities: []string{"create", "read", "update", "delete", "list", "sudo"}}
	// //policy.Paths = append(policy.Paths, &rootPathRules, &caPathRules, &enrollerPathRules)
	// policy.Paths = append(policy.Paths, &rootPathRules)

	// newPolicy := PolicyToString(*policy)

	// err = vs.client.Sys().PutPolicy("enroller-ca-policy", newPolicy)
	// if err != nil {
	// 	level.Error(vs.logger).Log("err", err, "msg", "Error while modifying enroller-ca-policy policy on Vault")
	// 	return err
	// }

	_, err = vs.client.Logical().Write(vs.pkiPath+CAName+"/roles/enroller", map[string]interface{}{
		"allow_any_name": true,
		"ttl":            strconv.Itoa(enrollerTTL) + "h",
		"max_ttl":        strconv.Itoa(enrollerTTL) + "h",
		"key_type":       "any",
	})
	if err != nil {
		level.Error(vs.logger).Log("err", err, "msg", "Could not create a new role for "+CAName+" CA on Vault")
		return err
	}

	_, err = vs.client.Logical().Write(vs.pkiPath+CAName+"/config/urls", map[string]interface{}{
		"ocsp_servers": []string{
			vs.ocspUrl,
		},
	})

	if err != nil {
		level.Error(vs.logger).Log("err", err, "msg", "Could not configure OCSP information for "+CAName+" CA on Vault")
		return err
	}

	return nil
}

func (vs *vaultSecrets) DeleteCA(ctx context.Context, ca string) error {

	certsToRevoke, err := vs.GetIssuedCerts(ctx, ca)
	for i := 0; i < len(certsToRevoke.Certs); i++ {
		err = vs.DeleteCert(ca, certsToRevoke.Certs[i].SerialNumber)
		level.Warn(vs.logger).Log("err", err, "msg", "Could not revoke issued cert with serial number "+certsToRevoke.Certs[i].SerialNumber)
	}

	_, err = vs.client.Logical().Delete(vs.pkiPath + ca + "/root")
	if err != nil {
		level.Error(vs.logger).Log("err", err, "msg", "Could not delete "+ca+" certificate from Vault")
		return err
	}
	_, err = vs.client.Logical().Delete(vs.pkiPath + ca + "/roles/enroller")
	if err != nil {
		level.Error(vs.logger).Log("err", err, "msg", "Could not delete enroller role from CA "+ca)
		return err
	}
	return nil
}

func (vs *vaultSecrets) GetCert(caName string, serialNumber string) (secrets.Cert, error) {
	certResponse, err := vs.client.Logical().Read(vs.pkiPath + caName + "/cert/" + serialNumber)
	if err != nil {
		level.Error(vs.logger).Log("err", err, "msg", "Could not read cert with serial number "+serialNumber+" from CA "+caName)
		return secrets.Cert{}, err
	}
	cert, err := DecodeCert([]byte(certResponse.Data["certificate"].(string)))
	if err != nil {
		level.Error(vs.logger).Log("err", err, "msg", "Could not decode certificate serial number "+serialNumber+" from CA "+caName)
		return secrets.Cert{}, err
	}
	pubKey, keyType, keyBits, keyStrength := getPublicKeyInfo(cert)
	hasExpired := cert.NotAfter.Before(time.Now())
	status := "issued"
	if hasExpired {
		status = "expired"
	}
	revocation_time, err := certResponse.Data["revocation_time"].(json.Number).Int64()
	if err != nil {
		err = errors.New("revocation_time not an INT for cert " + serialNumber + ".")
		level.Warn(vs.logger).Log("err", err)
	}
	if revocation_time != 0 {
		status = "revoked"
	}
	return secrets.Cert{
		SerialNumber: insertNth(toHexInt(cert.SerialNumber), 2),
		Status:       status,
		Name:         caName,
		CertContent: secrets.CertContent{
			CerificateBase64: base64.StdEncoding.EncodeToString([]byte(certResponse.Data["certificate"].(string))),
			PublicKeyBase64:  base64.StdEncoding.EncodeToString([]byte(pubKey)),
		},
		Subject: secrets.Subject{
			C:  strings.Join(cert.Subject.Country, " "),
			ST: strings.Join(cert.Subject.Province, " "),
			L:  strings.Join(cert.Subject.Locality, " "),
			O:  strings.Join(cert.Subject.Organization, " "),
			OU: strings.Join(cert.Subject.OrganizationalUnit, " "),
			CN: cert.Subject.CommonName,
		},
		KeyMetadata: secrets.KeyInfo{
			KeyType:     keyType,
			KeyBits:     keyBits,
			KeyStrength: keyStrength,
		},
		ValidFrom: cert.NotBefore.String(),
		ValidTo:   cert.NotAfter.String(),
	}, nil
}

func (vs *vaultSecrets) GetIssuedCerts(ctx context.Context, caName string) (secrets.Certs, error) {
	var Certs secrets.Certs
	Certs.Certs = make([]secrets.Cert, 0)

	if caName == "" {
		cas, err := vs.GetCAs(ctx)
		if err != nil {
			level.Error(vs.logger).Log("err", err, "msg", "Could not get CAs from Vault")
			return secrets.Certs{}, err
		}
		for _, cert := range cas.Certs {
			if cert.Name != "" {
				certsSubset, err := vs.GetIssuedCerts(ctx, cert.Name)
				if err != nil {
					level.Error(vs.logger).Log("err", err, "msg", "Error while getting issued cert subset for CA "+cert.Name)
					continue
				}
				Certs.Certs = append(Certs.Certs, certsSubset.Certs...)
			}
		}
	} else {
		resp, err := vs.client.Logical().List(vs.pkiPath + caName + "/certs")
		if err != nil {
			level.Error(vs.logger).Log("err", err, "msg", "Could not read "+caName+" mount path from Vault")
			return secrets.Certs{}, err
		}

		caCert, err := vs.GetCA(ctx, caName)
		if err != nil {
			level.Error(vs.logger).Log("err", err, "msg", "Could not get CA cert for "+caName)
			return secrets.Certs{}, err
		}

		for _, elem := range resp.Data["keys"].([]interface{}) {
			certSerialID := elem.(string)
			if caCert.SerialNumber == certSerialID {
				continue
			}
			certResponse, err := vs.client.Logical().Read(vs.pkiPath + caName + "/cert/" + certSerialID)
			if err != nil {
				level.Error(vs.logger).Log("err", err, "msg", "Could not read certificate "+certSerialID+" from CA "+caName)
				continue
			}
			cert, err := DecodeCert([]byte(certResponse.Data["certificate"].(string)))
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
				Name:         caName,
				CertContent: secrets.CertContent{
					CerificateBase64: base64.StdEncoding.EncodeToString([]byte(certResponse.Data["certificate"].(string))),
					PublicKeyBase64:  base64.StdEncoding.EncodeToString([]byte(pubKey)),
				},
				Subject: secrets.Subject{
					C:  strings.Join(cert.Subject.Country, " "),
					ST: strings.Join(cert.Subject.Province, " "),
					L:  strings.Join(cert.Subject.Locality, " "),
					O:  strings.Join(cert.Subject.Organization, " "),
					OU: strings.Join(cert.Subject.OrganizationalUnit, " "),
					CN: cert.Subject.CommonName,
				},
				KeyMetadata: secrets.KeyInfo{
					KeyType:     keyType,
					KeyBits:     keyBits,
					KeyStrength: keyStrength,
				},
				ValidFrom: cert.NotBefore.String(),
				ValidTo:   cert.NotAfter.String(),
			})
		}
	}
	return Certs, nil

}

func (vs *vaultSecrets) DeleteCert(caName string, serialNumber string) error {
	options := map[string]interface{}{
		"serial_number": serialNumber,
	}
	_, err := vs.client.Logical().Write(vs.pkiPath+caName+"/revoke", options)
	if err != nil {
		level.Error(vs.logger).Log("err", err, "msg", "Could not revoke cert with serial number "+serialNumber+" from CA "+caName)
		return err
	}
	return nil
}

func insertNth(s string, n int) string {
	if len(s)%2 != 0 {
		s = "0" + s
	}
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

func DecodeCert(cert []byte) (x509.Certificate, error) {
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

func (vs *vaultSecrets) hasEnrollerRole(caName string) bool {
	data, _ := vs.client.Logical().Read(vs.pkiPath + caName + "/roles/enroller")
	if data == nil {
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
		if keyBits < 2048 {
			keyStrength = "low"
		} else if keyBits >= 2048 && keyBits < 3072 {
			keyStrength = "medium"
		} else {
			keyStrength = "high"
		}
	case "ECDSA":
		if keyBits <= 128 {
			keyStrength = "low"
		} else if keyBits > 128 && keyBits < 256 {
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
