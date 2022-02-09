package lamassuca

import (
	"context"
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
	"github.com/opentracing/opentracing-go"
)

type LamassuCaClient interface {
	GetCAs(ctx context.Context, caType string) (Certs, error)
	SignCertificateRequest(ctx context.Context, signingCaName string, csr *x509.CertificateRequest, caType string, signVerbatim bool) (*x509.Certificate, error)
	RevokeCert(ctx context.Context, IssuerName string, serialNumberToRevoke string, caType string) error
	GetCert(ctx context.Context, IssuerName string, SerialNumber string, caType string) (Cert, error)
}

type LamassuCaClientConfig struct {
	client BaseClient
	logger log.Logger
}

func NewLamassuCaClient(lamassuCaUrl string, lamassuCaCert string, clientCertFile string, clientCertKey string, logger log.Logger) (LamassuCaClient, error) {
	caPem, err := ioutil.ReadFile(lamassuCaCert)
	if err != nil {
		return nil, err
	}
	cert, err := tls.LoadX509KeyPair(clientCertFile, clientCertKey)

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

func (c *LamassuCaClientConfig) GetCAs(ctx context.Context, caType string) (Certs, error) {
	c.logger = ctx.Value("LamassuLogger").(log.Logger)
	parentSpan := opentracing.SpanFromContext(ctx)

	span := opentracing.StartSpan("lamassu-ca: GetCAs request", opentracing.ChildOf(parentSpan.Context()))
	span_id := fmt.Sprintf("%s", span)
	req, err := c.client.NewRequest("GET", "v1/"+caType, nil)
	if err != nil {
		level.Error(c.logger).Log("err", err, "msg", "Could not create GetCAs request")
		return Certs{}, err
	}
	req.Header.Set("uber-trace-id", span_id)
	respBody, _, err := c.client.Do(req)
	span.Finish()
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

func (c *LamassuCaClientConfig) SignCertificateRequest(ctx context.Context, signingCaName string, csr *x509.CertificateRequest, caType string, signVerbatim bool) (*x509.Certificate, error) {
	c.logger = ctx.Value("LamassuLogger").(log.Logger)

	parentSpan := opentracing.SpanFromContext(ctx)

	csrBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr.Raw})
	base64CsrContent := base64.StdEncoding.EncodeToString(csrBytes)
	body := map[string]interface{}{
		"csr":           base64CsrContent,
		"sign_verbatim": signVerbatim,
	}
	span := opentracing.StartSpan("lamassu-ca: Sign Certificate request", opentracing.ChildOf(parentSpan.Context()))
	span_id := fmt.Sprintf("%s", span)

	req, err := c.client.NewRequest("POST", "v1/"+caType+"/"+signingCaName+"/sign", body)
	req.Header.Set("uber-trace-id", span_id)

	if err != nil {
		level.Error(c.logger).Log("err", err, "msg", "Could not create Sign Certificate request")
		return nil, err
	}
	respBody, _, err := c.client.Do(req)
	span.Finish()
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

func (c *LamassuCaClientConfig) RevokeCert(ctx context.Context, IssuerName string, serialNumberToRevoke string, caType string) error {
	c.logger = ctx.Value("LamassuLogger").(log.Logger)
	parentSpan := opentracing.SpanFromContext(ctx)

	span := opentracing.StartSpan("lamassu-ca: Revoke Certificate request", opentracing.ChildOf(parentSpan.Context()))
	span_id := fmt.Sprintf("%s", span)
	req, err := c.client.NewRequest("DELETE", "v1/"+caType+"/"+IssuerName+"/cert/"+serialNumberToRevoke, nil)
	req.Header.Set("uber-trace-id", span_id)
	if err != nil {
		span.Finish()
		level.Error(c.logger).Log("err", err, "msg", "Could not create Revoke Certificate request")
		return err
	}
	_, _, err = c.client.Do(req)
	span.Finish()
	if err != nil {
		level.Error(c.logger).Log("err", err, "msg", "Error in http request")
		return err
	}

	return nil
}

func (c *LamassuCaClientConfig) GetCert(ctx context.Context, IssuerName string, SerialNumber string, caType string) (Cert, error) {
	c.logger = ctx.Value("LamassuLogger").(log.Logger)
	parentSpan := opentracing.SpanFromContext(ctx)

	span := opentracing.StartSpan("lamassu-ca: Get Certificate request", opentracing.ChildOf(parentSpan.Context()))
	span_id := fmt.Sprintf("%s", span)
	req, err := c.client.NewRequest("GET", "v1/"+caType+"/"+IssuerName+"/cert/"+SerialNumber, nil)
	req.Header.Set("uber-trace-id", span_id)
	if err != nil {
		span.Finish()
		level.Error(c.logger).Log("err", err, "msg", "Could not create Get Certificate request")
		return Cert{}, err
	}
	respBody, _, err := c.client.Do(req)
	span.Finish()
	if err != nil {
		level.Error(c.logger).Log("err", err, "msg", "Error in http request")
		return Cert{}, err
	}

	var cert Cert
	jsonString, _ := json.Marshal(respBody)
	json.Unmarshal(jsonString, &cert)

	return cert, nil

}
