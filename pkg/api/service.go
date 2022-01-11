package api

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"os"
	"sync"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	"github.com/lamassuiot/lamassu-ca/pkg/secrets"
	"github.com/streadway/amqp"
)

type Service interface {
	GetSecretProviderName(ctx context.Context) string
	Health(ctx context.Context) bool
	GetCAs(ctx context.Context) (secrets.Certs, error)
	CreateCA(ctx context.Context, caName string, ca secrets.Cert) error
	ImportCA(ctx context.Context, caName string, ca secrets.CAImport) error
	DeleteCA(ctx context.Context, caName string) error
	GetIssuedCerts(ctx context.Context, caName string) (secrets.Certs, error)
	GetCert(ctx context.Context, caName string, serialNumber string) (secrets.Cert, error)
	DeleteCert(ctx context.Context, caName string, serialNumber string) error
	SignCertificate(ctx context.Context, signingCaName string, csr x509.CertificateRequest) (string, error)
}

type caService struct {
	mtx             sync.RWMutex
	logger          log.Logger
	secrets         secrets.Secrets
	sendMessageFunc func(string, string)
}

var (
	//Client
	errInvalidCA = errors.New("invalid CA, does not exist")

	//Server
	ErrGetCAs    = errors.New("unable to get CAs from secret engine")
	errGetCAInfo = errors.New("unable to get CA information from secret engine")
	errDeleteCA  = errors.New("unable to delete CA from secret engine")
)

func NewCAService(logger log.Logger, secrets secrets.Secrets, amqpConnection *amqp.Connection) Service {
	amqpChannel, err := amqpConnection.Channel()
	if err != nil {
		level.Error(logger).Log("err", err, "msg", "Failed to open an AMQP channel")
		os.Exit(1)
	}

	// err = amqpChannel.ExchangeDeclare(
	// 	"lamassu_exchange", // name
	// 	"topic",            // type
	// 	true,               // durable
	// 	false,              // auto-deleted
	// 	false,              // internal
	// 	false,              // no-wait
	// 	nil,                // arguments
	// )
	if err != nil {
		level.Error(logger).Log("err", err, "msg", "Failed to declare an AMQP exchange")
		os.Exit(1)
	}

	sendMessageFunc := func(topic string, msg string) {
		err = amqpChannel.Publish(
			"lamassu_exchange", // exchange
			topic,              // routing key
			false,              // mandatory
			false,              // immediate
			amqp.Publishing{
				ContentType: "text/plain",
				Body:        []byte(msg),
			})

		if err != nil {
			level.Error(logger).Log("err", err, "msg", "Failed to send AMQP message")
			os.Exit(1)
		}

		level.Debug(logger).Log("msg", "AQMP message sent", msg)
	}

	return &caService{
		secrets:         secrets,
		sendMessageFunc: sendMessageFunc,
		logger:          logger,
	}
}

func (s *caService) GetSecretProviderName(ctx context.Context) string {
	return s.secrets.GetSecretProviderName(ctx)
}

func (s *caService) Health(ctx context.Context) bool {
	return true
}

func (s *caService) GetCAs(ctx context.Context) (secrets.Certs, error) {

	CAs, err := s.secrets.GetCAs(ctx)
	if err != nil {
		return secrets.Certs{}, ErrGetCAs
	}

	jsonCAs, _ := json.Marshal(CAs)

	s.sendMessageFunc("lamassu.ca.getcas", string(jsonCAs))
	level.Info(s.logger).Log("msg", "Lamassu GET CAS")
	return CAs, nil
}

func (s *caService) CreateCA(ctx context.Context, caName string, ca secrets.Cert) error {
	err := s.secrets.CreateCA(caName, ca)
	if err != nil {
		return err
	}

	return nil
}
func (s *caService) ImportCA(ctx context.Context, caName string, caImport secrets.CAImport) error {
	err := s.secrets.ImportCA(caName, caImport)
	if err != nil {
		return err
	}
	return nil
}

func (s *caService) DeleteCA(ctx context.Context, CA string) error {
	err := s.secrets.DeleteCA(ctx, CA)
	if err != nil {
		return err
	}
	return nil
}

func (s *caService) GetIssuedCerts(ctx context.Context, caName string) (secrets.Certs, error) {
	certs, err := s.secrets.GetIssuedCerts(ctx, caName)
	if err != nil {
		return secrets.Certs{}, err
	}
	return certs, nil
}
func (s *caService) GetCert(ctx context.Context, caName string, serialNumber string) (secrets.Cert, error) {
	certs, err := s.secrets.GetCert(caName, serialNumber)
	if err != nil {
		return secrets.Cert{}, err
	}
	return certs, nil
}

func (s *caService) DeleteCert(ctx context.Context, caName string, serialNumber string) error {
	err := s.secrets.DeleteCert(caName, serialNumber)
	if err != nil {
		return err
	}
	return nil
}
func (s *caService) SignCertificate(ctx context.Context, caName string, csr x509.CertificateRequest) (string, error) {
	cert, err := s.secrets.SignCertificate(caName, &csr)
	if err != nil {
		return "", err
	}
	return cert, nil
}
