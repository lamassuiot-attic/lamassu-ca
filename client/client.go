package lamassuca

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io/ioutil"
	"net/http"
	"net/url"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
)

type LamassuCaClient interface {
	GetCAs() (Certs, error)
	SignCertificateRequest(signingCaName string, csr *x509.CertificateRequest) (*x509.Certificate, error)
}

type LamassuCaClientConfig struct {
	client BaseClient
	logger log.Logger
}

func NewLamassuCaClient(lamassuCaUrl string, lamassuCaCert string, logger log.Logger) (LamassuCaClient, error) {
	caPem, err := ioutil.ReadFile(lamassuCaCert)
	if err != nil {
		return nil, err
	}

	certPool := x509.NewCertPool()
	certPool.AppendCertsFromPEM(caPem)

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			RootCAs: certPool,
		},
	}

	httpClient := &http.Client{Transport: tr}

	u, err := url.Parse(lamassuCaUrl)
	if err != nil {
		return nil, err
	}

	return &LamassuCaClientConfig{
		client: NewBaseClient(u, httpClient),
		logger: logger,
	}, nil
}

func (c *LamassuCaClientConfig) GetCAs() (Certs, error) {
	req, err := c.client.NewRequest("GET", "v1/ca", nil)
	if err != nil {
		level.Error(c.logger).Log("err", err, "msg", "Could not create GetCAs request")
		return Certs{}, err
	}

	respBody, _, err := c.client.Do(req)
	if err != nil {
		level.Error(c.logger).Log("err", err, "msg", "Error in http request")
		return Certs{}, err
	}

	certsArrayInterface := respBody.([]interface{})
	var certs Certs
	for _, item := range certsArrayInterface {
		cert := Cert{}
		jsonString, _ := json.Marshal(item)
		json.Unmarshal(jsonString, &cert)
		certs.Certs = append(certs.Certs, cert)
	}

	return certs, nil
}

func (c *LamassuCaClientConfig) SignCertificateRequest(signingCaName string, csr *x509.CertificateRequest) (*x509.Certificate, error) {
	csrBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr.Raw})
	base64CsrContent := base64.StdEncoding.EncodeToString(csrBytes)
	body := map[string]interface{}{
		"csr": base64CsrContent,
	}

	req, err := c.client.NewRequest("POST", "v1/ca/"+signingCaName+"/sign", body)
	if err != nil {
		level.Error(c.logger).Log("err", err, "msg", "Could not create GetCAs request")
		return nil, err
	}

	respBody, _, err := c.client.Do(req)

	var cert Certificate
	jsonString, _ := json.Marshal(respBody)
	json.Unmarshal(jsonString, &cert)

	data, _ := base64.StdEncoding.DecodeString(cert.Cert)
	block, _ := pem.Decode([]byte(data))
	x509Certificate, _ := x509.ParseCertificate(block.Bytes)

	return x509Certificate, nil
}
