package api

import (
	"context"
	"crypto/x509"
	"fmt"
	"time"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	"github.com/lamassuiot/lamassu-ca/pkg/secrets"
	"github.com/streadway/amqp"
)

type amqpMiddleware struct {
	amqpChannel *amqp.Channel
	logger      log.Logger
	next        Service
}

func NewAmqpMiddleware(channel *amqp.Channel, logger log.Logger) Middleware {
	return func(next Service) Service {
		return &amqpMiddleware{
			amqpChannel: channel,
			logger:      logger,
			next:        next,
		}
	}
}

func (mw *amqpMiddleware) GetSecretProviderName(ctx context.Context) (providerName string) {
	defer func(begin time.Time) {

	}(time.Now())

	return mw.next.GetSecretProviderName(ctx)
}

func (mw *amqpMiddleware) Health(ctx context.Context) bool {
	defer func(begin time.Time) {

	}(time.Now())
	return mw.next.Health(ctx)
}

func (mw *amqpMiddleware) GetCAs(ctx context.Context, caType secrets.CAType) (CAs secrets.Certs, err error) {
	defer func(begin time.Time) {

	}(time.Now())

	return mw.next.GetCAs(ctx, caType)
}

func (mw *amqpMiddleware) CreateCA(ctx context.Context, caType secrets.CAType, caName string, ca secrets.Cert) (cretedCa secrets.Cert, err error) {
	defer func(begin time.Time) {
		err = mw.amqpChannel.Publish("", "create_ca_queue", false, false, amqp.Publishing{
			ContentType: "text/json",
			Body:        []byte(fmt.Sprintf(`{"jsonrpc": "2.0", "method": "CREATE_CA", "params": {"ca_name":"%s", "serial_number": "%s", "ca_cert":"%s"}}}`, cretedCa.Name, cretedCa.SerialNumber, cretedCa.CertContent.CerificateBase64)),
		})
		if err != nil {
			level.Error(mw.logger).Log("msg", "Error while publishing to AMQP queue", "err", err)
		}
	}(time.Now())

	return mw.next.CreateCA(ctx, caType, caName, ca)
}

func (mw *amqpMiddleware) ImportCA(ctx context.Context, caType secrets.CAType, caName string, ca secrets.CAImport) (err error) {
	defer func(begin time.Time) {

	}(time.Now())
	return mw.next.ImportCA(ctx, caType, caName, ca)
}

func (mw *amqpMiddleware) DeleteCA(ctx context.Context, caType secrets.CAType, CA string) (err error) {
	defer func(begin time.Time) {

	}(time.Now())

	return mw.next.DeleteCA(ctx, caType, CA)
}

func (mw *amqpMiddleware) GetIssuedCerts(ctx context.Context, caType secrets.CAType, caName string) (certs secrets.Certs, err error) {
	defer func(begin time.Time) {

	}(time.Now())
	return mw.next.GetIssuedCerts(ctx, caType, caName)
}
func (mw *amqpMiddleware) GetCert(ctx context.Context, caType secrets.CAType, caName string, serialNumber string) (cert secrets.Cert, err error) {
	defer func(begin time.Time) {

	}(time.Now())

	return mw.next.GetCert(ctx, caType, caName, serialNumber)
}

func (mw *amqpMiddleware) DeleteCert(ctx context.Context, caType secrets.CAType, caName string, serialNumber string) (err error) {
	defer func(begin time.Time) {

	}(time.Now())
	return mw.next.DeleteCert(ctx, caType, caName, serialNumber)
}

func (mw *amqpMiddleware) SignCertificate(ctx context.Context, caType secrets.CAType, caName string, csr x509.CertificateRequest) (crt string, err error) {
	defer func(begin time.Time) {

	}(time.Now())
	return mw.next.SignCertificate(ctx, caType, caName, csr)
}
