package secrets

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
)

type Cert struct {
	// The status of the CA
	// required: true
	// example: issued | expired
	Status string `json:"status,omitempty"`

	// The serial number of the CA
	// required: true
	// example: 7e:36:13:a5:31:9f:4a:76:10:64:2e:9b:0a:11:07:b7:e6:3e:cf:94
	SerialNumber string `json:"serial_number,omitempty"`

	// The name/alias of the CA
	// required: true
	// example: Lamassu-CA
	Name string `json:"name,omitempty"`

	KeyMetadata PrivateKeyMetadataWithStregth `json:"key_metadata"`

	Subject Subject `json:"subject"`

	CertContent CertContent `json:"certificate"`

	// Expiration period of the new emmited CA
	// required: true
	// example: 262800h
	CaTTL int `json:"ca_ttl,omitempty"`

	EnrollerTTL int `json:"enroller_ttl,omitempty"`

	ValidFrom string `json:"valid_from"`
	ValidTo   string `json:"valid_to"`
}

type CAImport struct {
	PEMBundle string `json:"pem_bundle"`
	TTL       int    `json:"ttl"`
}
type CertContent struct {
	CerificateBase64 string `json:"pem_base64, omitempty"`
	PublicKeyBase64  string `json:"public_key_base64"`
}

type PrivateKey struct {
	Key     interface{}
	KeyType string
}

func (pk *PrivateKey) GetPEMString() (string, error) {
	switch key := pk.Key.(type) {
	case *rsa.PrivateKey:
		pemdata := pem.EncodeToMemory(
			&pem.Block{
				Type:  "RSA PRIVATE KEY",
				Bytes: x509.MarshalPKCS1PrivateKey(key),
			},
		)
		return string(pemdata), nil
	case *ecdsa.PrivateKey:
		x509Encoded, _ := x509.MarshalECPrivateKey(key)
		pemdata := pem.EncodeToMemory(
			&pem.Block{
				Type:  "PRIVATE KEY",
				Bytes: x509Encoded,
			},
		)
		return string(pemdata), nil
	default:
		return "", errors.New("unsupported format")
	}
}

type PrivateKeyMetadata struct {
	// Algorithm used to create CA key
	// required: true
	// example: RSA
	KeyType string `json:"type"`

	// Length used to create CA key
	// required: true
	// example: 4096
	KeyBits int `json:"bits"`
}

type PrivateKeyMetadataWithStregth struct {
	// Algorithm used to create CA key
	// required: true
	// example: RSA
	KeyType string `json:"type"`

	// Length used to create CA key
	// required: true
	// example: 4096
	KeyBits int `json:"bits"`

	// Strength of the key used to the create CA
	// required: true
	// example: low
	KeyStrength string `json:"strength"`
}

type Subject struct {
	// Common name of the CA certificate
	// required: true
	// example: Lamassu-Root-CA1-RSA4096
	CN string `json:"common_name"`

	// Organization of the CA certificate
	// required: true
	// example: Lamassu IoT
	O string `json:"organization"`

	// Organization Unit of the CA certificate
	// required: true
	// example: Lamassu IoT department 1
	OU string `json:"organization_unit"`

	// Country Name of the CA certificate
	// required: true
	// example: ES
	C string `json:"country"`

	// State of the CA certificate
	// required: true
	// example: Guipuzcoa
	ST string `json:"state"`

	// Locality of the CA certificate
	// required: true
	// example: Arrasate
	L string `json:"locality"`
}

type CAType int

const (
	DmsEnroller CAType = iota
	Pki
)

func ParseCAType(s string) (CAType, error) {
	switch s {
	case "dmsenroller":
		return DmsEnroller, nil
	case "pki":
		return Pki, nil
	}
	return -1, errors.New("CAType parsing error")
}

func (c CAType) ToVaultPath() string {
	switch c {
	case DmsEnroller:
		return "_internal/"
	case Pki:
		return "_pki/"
	}
	return "_pki"
}

// CAs represents a list of CAs with minimum information
// swagger:model

type Secrets interface {
	GetSecretProviderName(ctx context.Context) string

	GetCAs(ctx context.Context, caType CAType) ([]Cert, error)
	GetCA(ctx context.Context, caType CAType, caName string) (Cert, error)
	CreateCA(ctx context.Context, caType CAType, caName string, privateKeyMetadata PrivateKeyMetadata, subject Subject, caTTL int, enrollerTTL int) (Cert, error)
	ImportCA(ctx context.Context, caType CAType, caName string, certificate x509.Certificate, privateKey PrivateKey, enrollerTTL int) (Cert, error)
	DeleteCA(ctx context.Context, caType CAType, caName string) error

	GetIssuedCerts(ctx context.Context, caType CAType, caName string) ([]Cert, error)
	GetCert(ctx context.Context, caType CAType, caName string, serialNumber string) (Cert, error)
	DeleteCert(ctx context.Context, caType CAType, caName string, serialNumber string) error

	SignCertificate(ctx context.Context, caType CAType, CAcaName string, csr *x509.CertificateRequest, signVerbatim bool) (string, error)
}
