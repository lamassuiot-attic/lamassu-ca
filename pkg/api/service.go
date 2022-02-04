package api

import (
	"context"
	"crypto/x509"
	"errors"
	"sync"

	"github.com/go-kit/kit/log"
	"github.com/lamassuiot/lamassu-ca/pkg/secrets"
)

type Service interface {
	GetSecretProviderName(ctx context.Context) string
	Health(ctx context.Context) bool
	GetCAs(ctx context.Context, caType secrets.CAType) (secrets.Certs, error)
	CreateCA(ctx context.Context, caType secrets.CAType, caName string, ca secrets.Cert) (secrets.Cert, error)
	ImportCA(ctx context.Context, caType secrets.CAType, caName string, ca secrets.CAImport) error
	DeleteCA(ctx context.Context, caType secrets.CAType, caName string) error
	GetIssuedCerts(ctx context.Context, caType secrets.CAType, caName string) (secrets.Certs, error)
	GetCert(ctx context.Context, caType secrets.CAType, caName string, serialNumber string) (secrets.Cert, error)
	DeleteCert(ctx context.Context, caType secrets.CAType, caName string, serialNumber string) error
	SignCertificate(ctx context.Context, caType secrets.CAType, signingCaName string, csr x509.CertificateRequest) (string, error)
}

type caService struct {
	mtx     sync.RWMutex
	logger  log.Logger
	secrets secrets.Secrets
}

var (
	//Client
	errInvalidCA = errors.New("invalid CA, does not exist")

	//Server
	ErrGetCAs    = errors.New("unable to get CAs from secret engine")
	errGetCAInfo = errors.New("unable to get CA information from secret engine")
	//ErrDeleteCA         = errors.New("unable to delete CA from secret engine")
	ErrEmptyCA          = errors.New("CA name not defined")
	ErrEmtySerialNumber = errors.New("Certificate without Serial Number")
	ErrDeleteCA         = errors.New("Could not delete certificate from Vault")
	ErrDeleteCert       = errors.New("Could not revoke cert from CA")
	ErrImportCA         = errors.New("Could no create CA. Already exists")
)

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

func (s *caService) GetCAs(ctx context.Context, caType secrets.CAType) (secrets.Certs, error) {

	CAs, err := s.secrets.GetCAs(ctx, caType)
	if err != nil {
		return secrets.Certs{}, ErrGetCAs
	}

	return CAs, nil
}

func (s *caService) CreateCA(ctx context.Context, caType secrets.CAType, caName string, ca secrets.Cert) (secrets.Cert, error) {
	createdCa, err := s.secrets.CreateCA(ctx, caType, caName, ca)
	if err != nil {
		return createdCa, err
	}

	return createdCa, err
}
func (s *caService) ImportCA(ctx context.Context, caType secrets.CAType, caName string, caImport secrets.CAImport) error {
	err := s.secrets.ImportCA(ctx, caType, caName, caImport)
	if err != nil {
		return err
	}
	return nil
}

func (s *caService) DeleteCA(ctx context.Context, caType secrets.CAType, CA string) error {
	err := s.secrets.DeleteCA(ctx, caType, CA)
	if err != nil {
		return err
	}
	return nil
}

func (s *caService) GetIssuedCerts(ctx context.Context, caType secrets.CAType, caName string) (secrets.Certs, error) {
	certs, err := s.secrets.GetIssuedCerts(ctx, caType, caName)
	if err != nil {
		return secrets.Certs{}, err
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

func (s *caService) SignCertificate(ctx context.Context, caType secrets.CAType, caName string, csr x509.CertificateRequest) (string, error) {
	cert, err := s.secrets.SignCertificate(ctx, caType, caName, &csr)
	if err != nil {
		return "", err
	}
	return cert, nil
}
