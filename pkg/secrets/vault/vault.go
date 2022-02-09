package vault

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"math/big"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/lamassuiot/lamassu-ca/pkg/secrets"
	"github.com/lamassuiot/lamassu-ca/pkg/utils"
	"github.com/opentracing/opentracing-go"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"

	"github.com/hashicorp/go-cleanhttp"
	"github.com/hashicorp/vault/api"
)

type VaultSecrets struct {
	client   *api.Client
	roleID   string
	secretID string
	pkiPath  string
	ocspUrl  string
}

// This type implements the http.RoundTripper interface
type LoggingRoundTripper struct {
	next http.RoundTripper
	ctx  context.Context
}

func NewLoggingRoundTripper(next http.RoundTripper /*ctx context.Context*/) *LoggingRoundTripper {
	return &LoggingRoundTripper{
		next: next,
		//	ctx:  ctx,
	}
}

func (lrt LoggingRoundTripper) RoundTrip(req *http.Request) (res *http.Response, e error) {
	// Do "before sending requests" actions here.
	// Send the request, get the response (or the error)
	span := opentracing.StartSpan(req.URL.Path)
	res, e = lrt.next.RoundTrip(req)
	span.Finish()

	// Handle the result.
	if e != nil {
		// fmt.Printf("Error: %v", e)
	} else {
		// fmt.Printf("Received %v response\n", res.Status)
	}

	return
}

func NewVaultSecrets(address string, pkiPath string, roleID string, secretID string, CA string, unsealFile string, ocspUrl string, logger log.Logger) (*VaultSecrets, error) {

	client, err := CreateVaultSdkClient(address, CA, logger)
	if err != nil {
		return nil, errors.New("Could not create Vault API client: " + err.Error())
	}

	err = Unseal(client, unsealFile, logger)
	if err != nil {
		return nil, errors.New("Could not unseal Vault: " + err.Error())
	}

	err = Login(client, roleID, secretID)
	if err != nil {
		return nil, errors.New("Could not login into Vault: " + err.Error())
	}

	return &VaultSecrets{
		client:   client,
		pkiPath:  pkiPath,
		roleID:   roleID,
		secretID: secretID,
		ocspUrl:  ocspUrl,
	}, nil
}

func NewVaultSecretsWithClient(client *api.Client, address string, pkiPath string, roleID string, secretID string, CA string, unsealFile string, ocspUrl string, logger log.Logger) (*VaultSecrets, error) {
	return &VaultSecrets{
		client:   client,
		pkiPath:  pkiPath,
		roleID:   roleID,
		secretID: secretID,
		ocspUrl:  ocspUrl,
	}, nil
}

func CreateVaultSdkClient(vaultAddress string, vaultCaCertFilePath string, logger log.Logger) (*api.Client, error) {
	conf := api.DefaultConfig()
	httpClient := cleanhttp.DefaultPooledClient()
	httpTrasport := cleanhttp.DefaultPooledTransport()
	caPool, err := utils.CreateCAPool(vaultCaCertFilePath)

	if err != nil {
		return nil, err
	}

	httpTrasport.TLSClientConfig = &tls.Config{
		RootCAs: caPool,
	}
	httpClient.Transport = NewLoggingRoundTripper(httpTrasport)
	conf.HttpClient = httpClient
	conf.Address = strings.ReplaceAll(conf.Address, "https://127.0.0.1:8200", vaultAddress)
	// tlsConf := &api.TLSConfig{CACert: CA}
	// conf.ConfigureTLS(tlsConf)
	return api.NewClient(conf)

}

func Unseal(client *api.Client, unsealFile string, logger log.Logger) error {
	usnealJsonFile, err := os.Open(unsealFile)
	if err != nil {
		return err
	}

	unsealFileByteValue, _ := ioutil.ReadAll(usnealJsonFile)
	var unsealFileMap map[string]interface{}

	err = json.Unmarshal(unsealFileByteValue, &unsealFileMap)
	if err != nil {
		return err
	}

	unsealKeys := unsealFileMap["unseal_keys_hex"].([]interface{})

	providedSharesCount := 0
	sealed := true

	for sealed {
		unsealStatusProgress, err := client.Sys().Unseal(unsealKeys[providedSharesCount].(string))
		if err != nil {
			level.Error(logger).Log("err", "Error while unsealing vault", "provided_unseal_keys", providedSharesCount)
			return err
		}
		level.Debug(logger).Log("msg", "Unseal progress shares="+strconv.Itoa(unsealStatusProgress.N)+" threshold="+strconv.Itoa(unsealStatusProgress.T)+" remaining_shares="+strconv.Itoa(unsealStatusProgress.Progress))

		providedSharesCount++
		if !unsealStatusProgress.Sealed {
			level.Info(logger).Log("msg", "Vault is unsealed")
			sealed = false
		}
	}
	return nil
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

func (vs *VaultSecrets) GetSecretProviderName(ctx context.Context) string {
	return "Hashicorp_Vault"
}

func (vs *VaultSecrets) SignCertificate(ctx context.Context, caType secrets.CAType, caName string, csr *x509.CertificateRequest) (string, error) {

	csrBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr.Raw})
	options := map[string]interface{}{
		"csr":         string(csrBytes),
		"common_name": csr.Subject.CommonName,
	}

	parentSpan := opentracing.SpanFromContext(ctx)
	span := opentracing.StartSpan("lamassu-ca-api: vault-api POST /v1/"+vs.pkiPath+caType.ToVaultPath()+caName+"/sign-verbatim/enroller", opentracing.ChildOf(parentSpan.Context()))

	data, err := vs.client.Logical().Write(vs.pkiPath+caType.ToVaultPath()+caName+"/sign-verbatim/enroller", options)
	span.Finish()
	if err != nil {
		return "", err
	}
	certData := data.Data["certificate"]
	certPEMBlock, _ := pem.Decode([]byte(certData.(string)))
	if certPEMBlock == nil || certPEMBlock.Type != "CERTIFICATE" {
		err = errors.New("failed to decode PEM block containing certificate")
		return "", err
	}

	return base64.StdEncoding.EncodeToString([]byte(certData.(string))), nil
}

func (vs *VaultSecrets) GetCA(ctx context.Context, caType secrets.CAType, caName string) (secrets.Cert, error) {
	logger := ctx.Value("LamassuLogger").(log.Logger)
	parentSpan := opentracing.SpanFromContext(ctx)
	span := opentracing.StartSpan("lamassu-ca-api: vault-api GET /v1/"+vs.pkiPath+caType.ToVaultPath()+caName+"/cert/ca", opentracing.ChildOf(parentSpan.Context()))
	resp, err := vs.client.Logical().Read(vs.pkiPath + caType.ToVaultPath() + caName + "/cert/ca")
	span.Finish()

	if err != nil {
		level.Warn(logger).Log("err", err, "msg", "Could not read "+caName+" certificate from Vault")
		return secrets.Cert{}, err
	}
	if resp == nil {
		level.Warn(logger).Log("Mount path for PKI " + caName + " does not have a root CA")
		return secrets.Cert{}, err
	}

	certBytes := []byte(resp.Data["certificate"].(string))
	cert, err := DecodeCert(certBytes)
	if err != nil {
		err = errors.New("Cannot decode cert. Perhaps it is malphormed")
		level.Warn(logger).Log("err", err)
		return secrets.Cert{}, err
	}
	pubKey, keyType, keyBits, keyStrength := getPublicKeyInfo(cert)
	hasExpired := cert.NotAfter.Before(time.Now())
	status := "issued"
	if hasExpired {
		status = "expired"
	}

	if !vs.hasEnrollerRole(ctx, caType, caName) {
		status = "revoked"
	}

	return secrets.Cert{
		SerialNumber: InsertNth(ToHexInt(cert.SerialNumber), 2),
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

func (vs *VaultSecrets) GetCAs(ctx context.Context, caType secrets.CAType) (secrets.Certs, error) {
	logger := ctx.Value("LamassuLogger").(log.Logger)
	parentSpan := opentracing.SpanFromContext(ctx)
	span := opentracing.StartSpan("lamassu-ca-api: vault-api GET /v1/sys/mounts", opentracing.ChildOf(parentSpan.Context()))
	resp, err := vs.client.Sys().ListMounts()
	span.Finish()

	if err != nil {
		level.Error(logger).Log("err", err, "msg", "Could not obtain list of Vault mounts")
		return secrets.Certs{}, err
	}
	var CAs secrets.Certs

	for mount, mountOutput := range resp {
		if mountOutput.Type == "pki" && strings.HasPrefix(mount, vs.pkiPath) {
			caName := strings.TrimSuffix(mount, "/")
			caName = strings.TrimPrefix(caName, vs.pkiPath)
			if strings.Contains(caName, caType.ToVaultPath()) {
				caName = strings.TrimPrefix(caName, caType.ToVaultPath())
				cert, err := vs.GetCA(ctx, caType, caName)
				if err != nil {
					level.Error(logger).Log("err", err, "msg", "Could not get CA cert for "+caName)
					continue
				}
				CAs.Certs = append(CAs.Certs, cert)
			}
		}
	}
	level.Info(logger).Log("msg", strconv.Itoa(len(CAs.Certs))+" obtained from Vault mounts")
	return CAs, nil
}

func (vs *VaultSecrets) CreateCA(ctx context.Context, caType secrets.CAType, CAName string, ca secrets.Cert) (secrets.Cert, error) {
	logger := ctx.Value("LamassuLogger").(log.Logger)

	if len(CAName) == 0 {
		err := errors.New("CA name not defined")
		return secrets.Cert{}, err
	}
	err := vs.initPkiSecret(ctx, caType, CAName, ca.EnrollerTTL)
	if err != nil {
		return secrets.Cert{}, err
	}

	tuneOptions := map[string]interface{}{
		"max_lease_ttl": strconv.Itoa(ca.CaTTL) + "h",
	}
	parentSpan := opentracing.SpanFromContext(ctx)
	span := opentracing.StartSpan("lamassu-ca-api: vault-api POST /v1/sys/mounts/"+vs.pkiPath+caType.ToVaultPath()+CAName+"/tune", opentracing.ChildOf(parentSpan.Context()))
	_, err = vs.client.Logical().Write("/sys/mounts/"+vs.pkiPath+caType.ToVaultPath()+CAName+"/tune", tuneOptions)
	span.Finish()

	if err != nil {
		level.Error(logger).Log("err", err, "msg", "Could not tune CA "+CAName)
		return secrets.Cert{}, err
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
	span = opentracing.StartSpan("lamassu-ca-api: vault-api POST /v1/"+vs.pkiPath+caType.ToVaultPath()+CAName+"/root/generate/internal", opentracing.ChildOf(parentSpan.Context()))
	_, err = vs.client.Logical().Write(vs.pkiPath+caType.ToVaultPath()+CAName+"/root/generate/internal", options)
	span.Finish()

	if err != nil {
		level.Error(logger).Log("err", err, "msg", "Could not intialize the root CA certificate for "+CAName+" CA on Vault")
		return secrets.Cert{}, nil
	}

	return vs.GetCA(ctx, caType, CAName)
}

func (vs *VaultSecrets) ImportCA(ctx context.Context, caType secrets.CAType, CAName string, caImport secrets.CAImport) error {
	err := vs.initPkiSecret(ctx, caType, CAName, caImport.TTL)
	if err != nil {
		return errors.New("Could no create CA. Already exists")
	}
	options := map[string]interface{}{
		"pem_bundle": caImport.PEMBundle,
	}
	parentSpan := opentracing.SpanFromContext(ctx)
	span := opentracing.StartSpan("lamassu-ca-api: vault-api POST /v1/"+vs.pkiPath+caType.ToVaultPath()+CAName+"/config/ca", opentracing.ChildOf(parentSpan.Context()))
	_, err = vs.client.Logical().Write(vs.pkiPath+caType.ToVaultPath()+CAName+"/config/ca", options)
	span.Finish()

	return nil
}

func (vs *VaultSecrets) initPkiSecret(ctx context.Context, caType secrets.CAType, CAName string, enrollerTTL int) error {
	logger := ctx.Value("LamassuLogger").(log.Logger)

	mountInput := api.MountInput{Type: "pki", Description: ""}

	parentSpan := opentracing.SpanFromContext(ctx)
	span := opentracing.StartSpan("lamassu-ca-api: vault-api POST /v1/sys/mounts/"+vs.pkiPath+caType.ToVaultPath()+CAName, opentracing.ChildOf(parentSpan.Context()))
	err := vs.client.Sys().Mount(vs.pkiPath+caType.ToVaultPath()+CAName, &mountInput)
	span.Finish()

	if err != nil {
		level.Error(logger).Log("err", err, "msg", "Could not create a new pki mount point on Vaul.t")
		if strings.Contains(err.Error(), "path is already in use") {
			return errors.New("Could no create CA \"" + CAName + "\". Already exists")
		} else {
			return err
		}
	}
	span = opentracing.StartSpan("lamassu-ca-api: vault-api POST /v1/"+vs.pkiPath+caType.ToVaultPath()+CAName+"/roles/enroller", opentracing.ChildOf(parentSpan.Context()))
	_, err = vs.client.Logical().Write(vs.pkiPath+caType.ToVaultPath()+CAName+"/roles/enroller", map[string]interface{}{
		"allow_any_name": true,
		"ttl":            strconv.Itoa(enrollerTTL) + "h",
		"max_ttl":        strconv.Itoa(enrollerTTL) + "h",
		"key_type":       "any",
	})
	span.Finish()

	if err != nil {
		level.Error(logger).Log("err", err, "msg", "Could not create a new role for "+CAName+" CA on Vault")
		return err
	}
	span = opentracing.StartSpan("lamassu-ca-api: vault-api POST /v1/"+vs.pkiPath+caType.ToVaultPath()+CAName+"/config/urls", opentracing.ChildOf(parentSpan.Context()))
	_, err = vs.client.Logical().Write(vs.pkiPath+caType.ToVaultPath()+CAName+"/config/urls", map[string]interface{}{
		"ocsp_servers": []string{
			vs.ocspUrl,
		},
	})
	span.Finish()

	if err != nil {
		level.Error(logger).Log("err", err, "msg", "Could not configure OCSP information for "+CAName+" CA on Vault")
		return err
	}

	return nil
}

func (vs *VaultSecrets) DeleteCA(ctx context.Context, caType secrets.CAType, ca string) error {
	logger := ctx.Value("LamassuLogger").(log.Logger)

	if len(ca) == 0 {
		err := errors.New("CA name not defined")
		return err
	}
	certsToRevoke, err := vs.GetIssuedCerts(ctx, caType, ca)
	if len(certsToRevoke.Certs) > 0 {
		for i := 0; i < len(certsToRevoke.Certs); i++ {
			err = vs.DeleteCert(ctx, caType, ca, certsToRevoke.Certs[i].SerialNumber)
			level.Warn(logger).Log("err", err, "msg", "Could not revoke issued cert with serial number "+certsToRevoke.Certs[i].SerialNumber)
		}
	}

	parentSpan := opentracing.SpanFromContext(ctx)
	span := opentracing.StartSpan("lamassu-ca-api: vault-api DELETE /v1/"+vs.pkiPath+caType.ToVaultPath()+ca+"/root", opentracing.ChildOf(parentSpan.Context()))
	_, err = vs.client.Logical().Delete(vs.pkiPath + caType.ToVaultPath() + ca + "/root")
	span.Finish()

	if err != nil {

		level.Error(logger).Log("err", err, "msg", "Could not delete "+ca+" certificate from Vault")
		return errors.New("could not delete certificate from Vault")
	}
	span = opentracing.StartSpan("lamassu-ca-api: vault-api DELETE /v1/"+vs.pkiPath+caType.ToVaultPath()+ca+"/roles/enroller", opentracing.ChildOf(parentSpan.Context()))
	_, err = vs.client.Logical().Delete(vs.pkiPath + caType.ToVaultPath() + ca + "/roles/enroller")
	span.Finish()

	if err != nil {
		level.Error(logger).Log("err", err, "msg", "Could not delete enroller role from CA "+ca)
		return err
	}
	return nil
}

func (vs *VaultSecrets) GetCert(ctx context.Context, caType secrets.CAType, caName string, serialNumber string) (secrets.Cert, error) {
	logger := ctx.Value("LamassuLogger").(log.Logger)
	parentSpan := opentracing.SpanFromContext(ctx)
	span := opentracing.StartSpan("lamassu-ca-api: vault-api DELETE /v1/"+vs.pkiPath+caType.ToVaultPath()+caName+"/cert/"+serialNumber, opentracing.ChildOf(parentSpan.Context()))
	certResponse, err := vs.client.Logical().Read(vs.pkiPath + caType.ToVaultPath() + caName + "/cert/" + serialNumber)
	span.Finish()

	if err != nil {
		level.Error(logger).Log("err", err, "msg", "Could not read cert with serial number "+serialNumber+" from CA "+caName)
		return secrets.Cert{}, err
	}
	cert, err := DecodeCert([]byte(certResponse.Data["certificate"].(string)))
	if err != nil {
		level.Error(logger).Log("err", err, "msg", "Could not decode certificate serial number "+serialNumber+" from CA "+caName)
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
		level.Warn(logger).Log("err", err)
	}
	if revocation_time != 0 {
		status = "revoked"
	}
	return secrets.Cert{
		SerialNumber: InsertNth(ToHexInt(cert.SerialNumber), 2),
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

func (vs *VaultSecrets) GetIssuedCerts(ctx context.Context, caType secrets.CAType, caName string) (secrets.Certs, error) {
	logger := ctx.Value("LamassuLogger").(log.Logger)

	var Certs secrets.Certs
	Certs.Certs = make([]secrets.Cert, 0)

	if caName == "" {
		cas, err := vs.GetCAs(ctx, caType)
		if err != nil {
			level.Error(logger).Log("err", err, "msg", "Could not get CAs from Vault")
			return secrets.Certs{}, err
		}
		for _, cert := range cas.Certs {
			if cert.Name != "" {
				certsSubset, err := vs.GetIssuedCerts(ctx, caType, cert.Name)
				if err != nil {
					level.Error(logger).Log("err", err, "msg", "Error while getting issued cert subset for CA "+cert.Name)
					continue
				}
				Certs.Certs = append(Certs.Certs, certsSubset.Certs...)
			}
		}
	} else {
		parentSpan := opentracing.SpanFromContext(ctx)
		span := opentracing.StartSpan("lamassu-ca-api: vault-api LIST /v1/"+vs.pkiPath+caType.ToVaultPath()+caName+"/certs", opentracing.ChildOf(parentSpan.Context()))
		resp, err := vs.client.Logical().List(vs.pkiPath + caType.ToVaultPath() + caName + "/certs")
		span.Finish()

		if err != nil {
			level.Error(logger).Log("err", err, "msg", "Could not read "+caName+" mount path from Vault")
			return secrets.Certs{}, err
		}

		caCert, err := vs.GetCA(ctx, caType, caName)
		if err != nil {
			level.Error(logger).Log("err", err, "msg", "Could not get CA cert for "+caName)
			return secrets.Certs{}, err
		}

		if resp != nil && len(resp.Data["keys"].([]interface{})) > 0 {
			for _, elem := range resp.Data["keys"].([]interface{}) {
				certSerialID := elem.(string)
				if len(caCert.SerialNumber) == 0 {
					err = errors.New("Certificate without Serial Number")
					return secrets.Certs{}, err
				} else {
					if caCert.SerialNumber == certSerialID {
						continue
					}
					span = opentracing.StartSpan("lamassu-ca-api: vault-api GET /v1/"+vs.pkiPath+caType.ToVaultPath()+caName+"/cert"+certSerialID, opentracing.ChildOf(parentSpan.Context()))
					certResponse, err := vs.client.Logical().Read(vs.pkiPath + caType.ToVaultPath() + caName + "/cert/" + certSerialID)
					span.Finish()

					if err != nil {
						level.Error(logger).Log("err", err, "msg", "Could not read certificate "+certSerialID+" from CA "+caName)
						continue
					}
					cert, err := DecodeCert([]byte(certResponse.Data["certificate"].(string)))
					if err != nil {
						err = errors.New("Cannot decode cert " + certSerialID + ". Perhaps it is malphormed")
						level.Warn(logger).Log("err", err)
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
						level.Warn(logger).Log("err", err)
						continue
					}
					if revocation_time != 0 {
						status = "revoked"
					}

					Certs.Certs = append(Certs.Certs, secrets.Cert{
						SerialNumber: InsertNth(ToHexInt(cert.SerialNumber), 2),
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
		}
	}
	return Certs, nil

}

func (vs *VaultSecrets) DeleteCert(ctx context.Context, caType secrets.CAType, caName string, serialNumber string) error {
	logger := ctx.Value("LamassuLogger").(log.Logger)

	options := map[string]interface{}{
		"serial_number": serialNumber,
	}
	parentSpan := opentracing.SpanFromContext(ctx)
	span := opentracing.StartSpan("lamassu-ca-api: vault-api POST /v1/"+vs.pkiPath+caType.ToVaultPath()+caName+"/revoke serialnumber="+serialNumber, opentracing.ChildOf(parentSpan.Context()))
	_, err := vs.client.Logical().Write(vs.pkiPath+caType.ToVaultPath()+caName+"/revoke", options)
	span.Finish()

	if err != nil {
		level.Error(logger).Log("err", err, "msg", "Could not revoke cert with serial number "+serialNumber+" from CA "+caName)
		err = errors.New("Could not revoke cert from CA")
		return err
	}
	return nil
}

func (vs *VaultSecrets) hasEnrollerRole(ctx context.Context, caType secrets.CAType, caName string) bool {
	parentSpan := opentracing.SpanFromContext(ctx)
	span := opentracing.StartSpan("lamassu-ca-api: vault-api GET /v1/"+vs.pkiPath+caType.ToVaultPath()+caName+"/roles/enroller", opentracing.ChildOf(parentSpan.Context()))
	data, _ := vs.client.Logical().Read(vs.pkiPath + caType.ToVaultPath() + caName + "/roles/enroller")
	span.Finish()

	if data == nil {
		return false
	} else {
		return true
	}
}

func InsertNth(s string, n int) string {
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

func ToHexInt(n *big.Int) string {
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
