package service

import (
	"context"
	"crypto/x509"
	"sync"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	"github.com/lamassuiot/lamassu-ca/pkg/server/secrets"
)

type Service interface {
	GetSecretProviderName(ctx context.Context) string
	Health(ctx context.Context) bool
	GetCAs(ctx context.Context, caType secrets.CAType) ([]secrets.Cert, error)
	CreateCA(ctx context.Context, caType secrets.CAType, caName string, privateKeyMetadata secrets.PrivateKeyMetadata, subject secrets.Subject, caTTL int, enrollerTTL int) (secrets.Cert, error)
	ImportCA(ctx context.Context, caType secrets.CAType, caName string, certificate x509.Certificate, privateKey secrets.PrivateKey, enrollerTTL int) (secrets.Cert, error)
	DeleteCA(ctx context.Context, caType secrets.CAType, caName string) error
	GetIssuedCerts(ctx context.Context, caType secrets.CAType, caName string) ([]secrets.Cert, error)
	GetCert(ctx context.Context, caType secrets.CAType, caName string, serialNumber string) (secrets.Cert, error)
	DeleteCert(ctx context.Context, caType secrets.CAType, caName string, serialNumber string) error
	SignCertificate(ctx context.Context, caType secrets.CAType, signingCaName string, csr x509.CertificateRequest, signVerbatim bool) (string, error)
}

type caService struct {
	mtx     sync.RWMutex
	logger  log.Logger
	secrets secrets.Secrets
}

func NewCAService(logger log.Logger, secrets secrets.Secrets) Service {

	return &caService{
		secrets: secrets,
		logger:  logger,
	}
}

func (s *caService) GetSecretProviderName(ctx context.Context) string {
	return s.secrets.GetSecretProviderName(ctx)
}

func (s *caService) Health(ctx context.Context) bool {
	return true
}

func (s *caService) GetCAs(ctx context.Context, caType secrets.CAType) ([]secrets.Cert, error) {

	CAs, err := s.secrets.GetCAs(ctx, caType)
	if err != nil {
		return []secrets.Cert{}, err
	}

	return CAs, nil
}

func (s *caService) CreateCA(ctx context.Context, caType secrets.CAType, caName string, privateKeyMetadata secrets.PrivateKeyMetadata, subject secrets.Subject, caTTL int, enrollerTTL int) (secrets.Cert, error) {
	createdCa, err := s.secrets.CreateCA(ctx, caType, caName, privateKeyMetadata, subject, caTTL, enrollerTTL)
	if err != nil {
		return secrets.Cert{}, err
	}
	return createdCa, err
}
func (s *caService) ImportCA(ctx context.Context, caType secrets.CAType, caName string, certificate x509.Certificate, privateKey secrets.PrivateKey, enrollerTTL int) (secrets.Cert, error) {
	ca, err := s.secrets.ImportCA(ctx, caType, caName, certificate, privateKey, enrollerTTL)
	if err != nil {
		return secrets.Cert{}, err
	}
	return ca, nil
}

func (s *caService) DeleteCA(ctx context.Context, caType secrets.CAType, CA string) error {
	certsToRevoke, err := s.GetIssuedCerts(ctx, caType, CA)
	if err != nil {
		return err
	}
	if len(certsToRevoke) > 0 {
		for i := 0; i < len(certsToRevoke); i++ {
			err = s.DeleteCert(ctx, caType, CA, certsToRevoke[i].SerialNumber)
			level.Warn(s.logger).Log("err", err, "msg", "Could not revoke issued cert with serial number "+certsToRevoke[i].SerialNumber)
		}
	}
	err = s.secrets.DeleteCA(ctx, caType, CA)
	if err != nil {
		return err
	}
	return nil
}

func (s *caService) GetIssuedCerts(ctx context.Context, caType secrets.CAType, caName string) ([]secrets.Cert, error) {
	certs, err := s.secrets.GetIssuedCerts(ctx, caType, caName)
	if err != nil {
		return []secrets.Cert{}, err
	}
	return certs, nil
}
func (s *caService) GetCert(ctx context.Context, caType secrets.CAType, caName string, serialNumber string) (secrets.Cert, error) {
	certs, err := s.secrets.GetCert(ctx, caType, caName, serialNumber)
	if err != nil {
		return secrets.Cert{}, err
	}
	return certs, nil
}

func (s *caService) DeleteCert(ctx context.Context, caType secrets.CAType, caName string, serialNumber string) error {
	err := s.secrets.DeleteCert(ctx, caType, caName, serialNumber)
	if err != nil {
		return err
	}
	return nil
}

func (s *caService) SignCertificate(ctx context.Context, caType secrets.CAType, caName string, csr x509.CertificateRequest, signVerbatim bool) (string, error) {
	cert, err := s.secrets.SignCertificate(ctx, caType, caName, &csr, signVerbatim)
	if err != nil {
		return "", err
	}
	return cert, nil
}
