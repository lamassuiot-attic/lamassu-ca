package lamassuca

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
)

type LamassuCaClient interface {
	GetCAs(caType string) (Certs, error)
	SignCertificateRequest(signingCaName string, csr *x509.CertificateRequest, caType string) (*x509.Certificate, error)
	RevokeDeviceCertRequest(IssuerName string, serialNumberToRevoke string, caType string) (*http.Response, error)
	GetDeviceCertRequest(IssuerName string, SerialNumber string, caType string) (*http.Response, error)
}

type LamassuCaClientConfig struct {
	client BaseClient
	logger log.Logger
}

func NewLamassuCaClient(lamassuCaUrl string, lamassuCaCert string, deviceManagerCertFile string, deviceManagerCertKey string, logger log.Logger) (LamassuCaClient, error) {
	caPem, err := ioutil.ReadFile(lamassuCaCert)
	if err != nil {
		return nil, err
	}
	cert, err := tls.LoadX509KeyPair(deviceManagerCertFile, deviceManagerCertKey)

	if err != nil {
		return nil, err
	}

	certPool := x509.NewCertPool()
	certPool.AppendCertsFromPEM(caPem)

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			RootCAs:      certPool,
			Certificates: []tls.Certificate{cert},
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

func (c *LamassuCaClientConfig) GetCAs(caType string) (Certs, error) {
	req, err := c.client.NewRequest("GET", "v1/"+caType, nil)
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

func (c *LamassuCaClientConfig) SignCertificateRequest(signingCaName string, csr *x509.CertificateRequest, caType string) (*x509.Certificate, error) {
	csrBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr.Raw})
	base64CsrContent := base64.StdEncoding.EncodeToString(csrBytes)
	body := map[string]interface{}{
		"csr": base64CsrContent,
	}
	req, err := c.client.NewRequest("POST", "v1/"+caType+"/"+signingCaName+"/sign", body)
	if err != nil {
		level.Error(c.logger).Log("err", err, "msg", "Could not create GetCAs request")
		return nil, err
	}

	respBody, _, err := c.client.Do(req)

	if err != nil {
		level.Error(c.logger).Log("err", err, "msg", "Error in http request")
		return nil, err
	}

	var cert Certificate
	jsonString, _ := json.Marshal(respBody)
	json.Unmarshal(jsonString, &cert)

	data, _ := base64.StdEncoding.DecodeString(cert.Cert)
	block, _ := pem.Decode([]byte(data))
	x509Certificate, _ := x509.ParseCertificate(block.Bytes)

	return x509Certificate, nil
}

func (c *LamassuCaClientConfig) RevokeDeviceCertRequest(IssuerName string, serialNumberToRevoke string, caType string) (*http.Response, error) {
	req, err := c.client.NewRequest("DELETE", "v1/"+caType+"/"+IssuerName+"/cert/"+serialNumberToRevoke, nil)
	if err != nil {
		return nil, err
	}
	_, resp, err := c.client.Do(req)

	if err != nil {
		level.Error(c.logger).Log("err", err, "msg", "Error in http request")
		return nil, err
	}

	fmt.Println(resp)
	return resp, nil
}

func (c *LamassuCaClientConfig) GetDeviceCertRequest(IssuerName string, SerialNumber string, caType string) (*http.Response, error) {
	req, err := c.client.NewRequest("GET", "v1/"+caType+"/"+IssuerName+"/cert/"+SerialNumber, nil)

	if err != nil {
		return nil, err
	}
	_, resp, err := c.client.Do(req)

	if err != nil {
		level.Error(c.logger).Log("err", err, "msg", "Error in http request")
		return nil, err
	}

	return resp, nil

}
