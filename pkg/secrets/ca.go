package secrets

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"log"
	"net/http"

	"github.com/lamassuiot/est"
)

type VaultService struct {
	secrets Secrets
}

func NewVaultService(secrets Secrets) *VaultService {
	return &VaultService{
		secrets: secrets,
	}
}

func (ca *VaultService) CACerts(ctx context.Context, aps string, req *http.Request) ([]*x509.Certificate, error) {

	var filteredCerts []*x509.Certificate

	if aps != "" {
		cert, err := ca.secrets.GetCA(aps)

		block, _ := pem.Decode([]byte(cert.CRT))
		if block == nil {
			panic("failed to parse certificate PEM")
		}
		crt, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			log.Println("Error on response.\n[ERROR] -", err)
		}
		filteredCerts = append(filteredCerts, crt)

		return filteredCerts, err
	}

	certs, err := ca.secrets.GetCAs(AllCAs)
	if err != nil {
		log.Println("Error getting CA certs.\n[ERROR] -", err)
	}

	for _, v := range certs.Certs {
		block, _ := pem.Decode([]byte(v.CRT))
		if block == nil {
			panic("failed to parse certificate PEM")
		}
		crt, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			log.Println("Error on response.\n[ERROR] -", err)
		}
		filteredCerts = append(filteredCerts, crt)
	}

	return filteredCerts, err
}

func (ca *VaultService) Enroll(ctx context.Context, csr *x509.CertificateRequest, aps string, r *http.Request) (*x509.Certificate, error) {

	bytes, err := ca.secrets.SignCertificate(aps, csr)
	if err != nil {
		log.Println("Error on enrolling.\n[ERROR] -", err)
		return nil, err
	}

	crt, err := x509.ParseCertificate(bytes)
	if err != nil {
		log.Println("Error on response.\n[ERROR] -", err)
	}
	return crt, nil
}

func (ca *VaultService) CSRAttrs(ctx context.Context, aps string, r *http.Request) (est.CSRAttrs, error) {
	return est.CSRAttrs{}, nil
}

func (ca *VaultService) Reenroll(ctx context.Context, cert *x509.Certificate, csr *x509.CertificateRequest, aps string, r *http.Request) (*x509.Certificate, error) {
	bytes, err := ca.secrets.SignCertificate(aps, csr)
	if err != nil {
		log.Println("Error on enrolling.\n[ERROR] -", err)
		return nil, err
	}

	crt, err := x509.ParseCertificate(bytes)
	if err != nil {
		log.Println("Error on response.\n[ERROR] -", err)
	}
	return crt, nil
}

func (ca *VaultService) ServerKeyGen(ctx context.Context, csr *x509.CertificateRequest, aps string, r *http.Request) (*x509.Certificate, []byte, error) {
	return nil, nil, nil
}

func (ca *VaultService) TPMEnroll(ctx context.Context, csr *x509.CertificateRequest, ekcerts []*x509.Certificate, ekPub, akPub []byte, aps string, r *http.Request) ([]byte, []byte, []byte, error) {
	return nil, nil, nil, nil
}
