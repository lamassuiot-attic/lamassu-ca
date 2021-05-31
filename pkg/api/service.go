package api

import (
	"context"
	"errors"
	"sync"

	"github.com/lamassuiot/lamassu-ca/pkg/secrets"
)

type Service interface {
	Health(ctx context.Context) bool
	GetCAs(ctx context.Context) (secrets.CAs, error)
	GetCACrt(ctx context.Context, caName string) (secrets.CACrt, error)
	CreateCA(ctx context.Context, caName string, ca secrets.CA) error
	ImportCA(ctx context.Context, caName string, ca secrets.CAImport) error
	DeleteCA(ctx context.Context, caName string) error
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

func (s *caService) GetCAs(ctx context.Context) (secrets.CAs, error) {
	CAs, err := s.secrets.GetCAs()
	if err != nil {
		return secrets.CAs{}, ErrGetCAs
	}
	return CAs, nil

}

func (s *caService) GetCACrt(ctx context.Context, caName string) (secrets.CACrt, error) {
	caCrt, err := s.secrets.GetCACrt(caName)
	if (secrets.CACrt{}) == caCrt {
		return caCrt, errInvalidCA
	}
	if err != nil {
		return secrets.CACrt{}, errGetCAInfo
	}
	return caCrt, nil

}

func (s *caService) CreateCA(ctx context.Context, caName string, ca secrets.CA) error {
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
	err := s.secrets.DeleteCA(CA)
	if err != nil {
		return err
	}
	return nil
}
