package api

import (
	"context"
	"crypto/x509"
	"errors"
	"sync"

	"github.com/lamassuiot/lamassu-ca/pkg/secrets"
)

type Service interface {
	Health(ctx context.Context) bool
	GetCAs(ctx context.Context) (secrets.Certs, error)
	CreateCA(ctx context.Context, caName string, ca secrets.Cert) error
	ImportCA(ctx context.Context, caName string, ca secrets.CAImport) error
	DeleteCA(ctx context.Context, caName string) error
	GetIssuedCerts(ctx context.Context, caName string) (secrets.Certs, error)
	GetCert(ctx context.Context, caName string, serialNumber string) (secrets.Cert, error)
	DeleteCert(ctx context.Context, caName string, serialNumber string) error
	SignCertificate(ctx context.Context, signingCaName string, csr x509.CertificateRequest) ([]byte, error)
}

type caService struct {
	mtx     sync.RWMutex
	secrets secrets.Secrets
}

var (
	//Client
	errInvalidCA = errors.New("invalid CA, does not exist")

	//Server
	ErrGetCAs    = errors.New("unable to get CAs from secret engine")
	errGetCAInfo = errors.New("unable to get CA information from secret engine")
	errDeleteCA  = errors.New("unable to delete CA from secret engine")
)

func NewCAService(secrets secrets.Secrets) Service {
	return &caService{
		secrets: secrets,
	}
}

func (s *caService) Health(ctx context.Context) bool {
	return true
}

func (s *caService) GetCAs(ctx context.Context) (secrets.Certs, error) {

	CAs, err := s.secrets.GetCAs(ctx)
	if err != nil {
		return secrets.Certs{}, ErrGetCAs
	}
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
func (s *caService) SignCertificate(ctx context.Context, caName string, csr x509.CertificateRequest) ([]byte, error) {
	cert, err := s.secrets.SignCertificate(caName, &csr)
	if err != nil {
		return nil, err
	}
	return cert, nil
}
