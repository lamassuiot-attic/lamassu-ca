package api

import (
	"context"
	"errors"
	"sync"

	"github.com/lamassuiot/enroller/pkg/ca/secrets"
)

type Service interface {
	Health(ctx context.Context) bool
	GetCAs(ctx context.Context) (secrets.CAs, error)
	GetCAInfo(ctx context.Context, CA string) (secrets.CAInfo, error)
	DeleteCA(ctx context.Context, CA string) error
}

type caService struct {
	mtx     sync.RWMutex
	secrets secrets.Secrets
}

var (
	//Client
	errInvalidCA = errors.New("invalid CA, does not exist")

	//Server
	errGetCAs    = errors.New("unable to get CAs from secret engine")
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
		return secrets.CAs{}, errGetCAs
	}
	return CAs, nil

}

func (s *caService) GetCAInfo(ctx context.Context, CA string) (secrets.CAInfo, error) {
	CAInfo, err := s.secrets.GetCAInfo(CA)
	if (secrets.CAInfo{}) == CAInfo {
		return CAInfo, errInvalidCA
	}
	if err != nil {
		return secrets.CAInfo{}, errGetCAInfo
	}
	return CAInfo, nil

}

func (s *caService) DeleteCA(ctx context.Context, CA string) error {
	err := s.secrets.DeleteCA(CA)
	if err != nil {
		return err
	}
	return nil
}
