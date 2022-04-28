package service

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"time"

	cloudevents "github.com/cloudevents/sdk-go/v2"
	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	"github.com/lamassuiot/lamassu-ca/pkg/server/secrets"
	"github.com/lamassuiot/lamassu-ca/pkg/server/utils"
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

func (mw *amqpMiddleware) GetCAs(ctx context.Context, caType secrets.CAType) (CAs []secrets.Cert, err error) {
	defer func(begin time.Time) {

	}(time.Now())

	return mw.next.GetCAs(ctx, caType)
}

func (mw *amqpMiddleware) CreateCA(ctx context.Context, caType secrets.CAType, caName string, privateKeyMetadata secrets.PrivateKeyMetadata, subject secrets.Subject, caTTL int, enrollerTTL int) (cretedCa secrets.Cert, err error) {
	defer func(begin time.Time) {
		if err == nil {
			event := utils.CreateEvent(ctx, "1.0", "lamassu/ca", "io.lamassu.ca.create")
			type CreateCAEvent struct {
				Name         string `json:"name"`
				SerialNumber string `json:"serial_number"`
				Cert         string `json:"cert"`
			}
			event.SetData(cloudevents.ApplicationJSON, CreateCAEvent{
				Name:         cretedCa.Name,
				SerialNumber: cretedCa.SerialNumber,
				Cert:         cretedCa.CertContent.CerificateBase64,
			})

			mw.sendAMQPMessage(event)
		}
	}(time.Now())

	return mw.next.CreateCA(ctx, caType, caName, privateKeyMetadata, subject, caTTL, enrollerTTL)
}

func (mw *amqpMiddleware) ImportCA(ctx context.Context, caType secrets.CAType, caName string, certificate x509.Certificate, privateKey secrets.PrivateKey, enrollerTTL int) (createdCa secrets.Cert, err error) {
	defer func(begin time.Time) {
		if err == nil {
			event := utils.CreateEvent(ctx, "1.0", "lamassu/ca", "io.lamassu.ca.import")
			type ImportCAEvent struct {
				Name         string `json:"name"`
				SerialNumber string `json:"serial_number"`
				Cert         string `json:"cert"`
			}
			event.SetData(cloudevents.ApplicationJSON, ImportCAEvent{
				Name:         createdCa.Name,
				SerialNumber: createdCa.SerialNumber,
				Cert:         createdCa.CertContent.CerificateBase64,
			})

			mw.sendAMQPMessage(event)
		}
	}(time.Now())
	return mw.next.ImportCA(ctx, caType, caName, certificate, privateKey, enrollerTTL)
}

func (mw *amqpMiddleware) DeleteCA(ctx context.Context, caType secrets.CAType, CA string) (err error) {
	defer func(begin time.Time) {
		if err == nil {
			event := utils.CreateEvent(ctx, "1.0", "lamassu/ca", "io.lamassu.ca.update")
			type DeleteCAEvent struct {
				Name   string `json:"name"`
				Status string `json:"status"`
			}
			event.SetData(cloudevents.ApplicationJSON, DeleteCAEvent{
				Name:   CA,
				Status: "REVOKED",
			})

			mw.sendAMQPMessage(event)
		}
	}(time.Now())

	return mw.next.DeleteCA(ctx, caType, CA)
}

func (mw *amqpMiddleware) GetIssuedCerts(ctx context.Context, caType secrets.CAType, caName string) (certs []secrets.Cert, err error) {
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
		if err == nil {
			event := utils.CreateEvent(ctx, "1.0", "lamassu/ca", "io.lamassu.cert.update")
			type DeleteCertEvent struct {
				Name         string `json:"name"`
				SerialNumber string `json:"serial_number"`
				Status       string `json:"status"`
			}
			event.SetData(cloudevents.ApplicationJSON, DeleteCertEvent{
				Name:         caName,
				SerialNumber: serialNumber,
				Status:       "REVOKED",
			})
			mw.sendAMQPMessage(event)
		}
	}(time.Now())
	return mw.next.DeleteCert(ctx, caType, caName, serialNumber)
}

func (mw *amqpMiddleware) SignCertificate(ctx context.Context, caType secrets.CAType, caName string, csr x509.CertificateRequest, signVerbatim bool) (crt string, err error) {
	defer func(begin time.Time) {

	}(time.Now())
	return mw.next.SignCertificate(ctx, caType, caName, csr, signVerbatim)
}

func (mw *amqpMiddleware) sendAMQPMessage(event cloudevents.Event) {
	eventBytes, marshalErr := json.Marshal(event)
	if marshalErr != nil {
		level.Error(mw.logger).Log("msg", "Error while serializing event", "err", marshalErr)
	}

	amqpErr := mw.amqpChannel.Publish("", "lamassu_events", false, false, amqp.Publishing{
		ContentType: "text/json",
		Body:        []byte(eventBytes),
	})
	if amqpErr != nil {
		level.Error(mw.logger).Log("msg", "Error while publishing to AMQP queue", "err", amqpErr)
	}
}
