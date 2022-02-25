package endpoint

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"math"

	"github.com/go-playground/validator/v10"
	"github.com/lamassuiot/lamassu-ca/pkg/server/api/errors"
	"github.com/lamassuiot/lamassu-ca/pkg/server/api/service"
	"github.com/lamassuiot/lamassu-ca/pkg/server/secrets"

	"github.com/go-kit/kit/endpoint"
	"github.com/go-kit/kit/tracing/opentracing"
	stdopentracing "github.com/opentracing/opentracing-go"
)

type Endpoints struct {
	HealthEndpoint         endpoint.Endpoint
	GetCAsEndpoint         endpoint.Endpoint
	CreateCAEndpoint       endpoint.Endpoint
	ImportCAEndpoint       endpoint.Endpoint
	DeleteCAEndpoint       endpoint.Endpoint
	GetIssuedCertsEndpoint endpoint.Endpoint
	GetCertEndpoint        endpoint.Endpoint
	SignCertEndpoint       endpoint.Endpoint
	DeleteCertEndpoint     endpoint.Endpoint
}

func MakeServerEndpoints(s service.Service, otTracer stdopentracing.Tracer) Endpoints {
	var healthEndpoint endpoint.Endpoint
	{
		healthEndpoint = MakeHealthEndpoint(s)
		healthEndpoint = opentracing.TraceServer(otTracer, "Health")(healthEndpoint)
	}

	var getCAsEndpoint endpoint.Endpoint
	{
		getCAsEndpoint = MakeGetCAsEndpoint(s)
		getCAsEndpoint = opentracing.TraceServer(otTracer, "GetCAs")(getCAsEndpoint)
	}

	var createCAEndpoint endpoint.Endpoint
	{
		createCAEndpoint = MakeCreateCAEndpoint(s)
		createCAEndpoint = opentracing.TraceServer(otTracer, "CreateCA")(createCAEndpoint)
	}

	var importCAEndpoint endpoint.Endpoint
	{
		importCAEndpoint = MakeImportCAEndpoint(s)
		importCAEndpoint = opentracing.TraceServer(otTracer, "ImportCA")(importCAEndpoint)
	}

	var deleteCAEndpoint endpoint.Endpoint
	{
		deleteCAEndpoint = MakeDeleteCAEndpoint(s)
		deleteCAEndpoint = opentracing.TraceServer(otTracer, "DeleteCA")(deleteCAEndpoint)
	}

	var getIssuedCertsEndpoint endpoint.Endpoint
	{
		getIssuedCertsEndpoint = MakeIssuedCertsEndpoint(s)
		getIssuedCertsEndpoint = opentracing.TraceServer(otTracer, "GetIssuedCerts")(getIssuedCertsEndpoint)
	}
	var getCertEndpoint endpoint.Endpoint
	{
		getCertEndpoint = MakeCertEndpoint(s)
		getCertEndpoint = opentracing.TraceServer(otTracer, "GetCert")(getCertEndpoint)
	}

	var signCertificateEndpoint endpoint.Endpoint
	{
		signCertificateEndpoint = MakeSignCertEndpoint(s)
		signCertificateEndpoint = opentracing.TraceServer(otTracer, "SignCertificate")(signCertificateEndpoint)
	}

	var deleteCertEndpoint endpoint.Endpoint
	{
		deleteCertEndpoint = MakeDeleteCertEndpoint(s)
		deleteCertEndpoint = opentracing.TraceServer(otTracer, "DeleteCert")(deleteCertEndpoint)
	}

	return Endpoints{
		HealthEndpoint:         healthEndpoint,
		GetCAsEndpoint:         getCAsEndpoint,
		CreateCAEndpoint:       createCAEndpoint,
		ImportCAEndpoint:       importCAEndpoint,
		DeleteCAEndpoint:       deleteCAEndpoint,
		GetIssuedCertsEndpoint: getIssuedCertsEndpoint,
		GetCertEndpoint:        getCertEndpoint,
		DeleteCertEndpoint:     deleteCertEndpoint,
		SignCertEndpoint:       signCertificateEndpoint,
	}
}

func MakeHealthEndpoint(s service.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		healthy := s.Health(ctx)
		return HealthResponse{Healthy: healthy}, nil
	}
}

func MakeGetCAsEndpoint(s service.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		req := request.(GetCAsRequest)

		caType, _ := secrets.ParseCAType(req.CaType)

		cas, err := s.GetCAs(ctx, caType)
		return cas, err
	}
}

func MakeCreateCAEndpoint(s service.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		req := request.(CreateCARequest)

		err = ValidateCreatrCARequest(req)
		if err != nil {
			valError := errors.ValidationError{
				Msg: err.Error(),
			}
			return nil, &valError
		}

		caType, _ := secrets.ParseCAType(req.CaType)

		ca, err := s.CreateCA(ctx, caType, req.CaName, secrets.PrivateKeyMetadata(req.CaPayload.KeyMetadata), secrets.Subject(req.CaPayload.Subject), req.CaPayload.CaTTL, req.CaPayload.EnrollerTTL)
		return ca, err
	}
}

func MakeDeleteCAEndpoint(s service.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		req := request.(DeleteCARequest)
		err = s.DeleteCA(ctx, req.CaType, req.CA)
		return nil, err
	}
}

func MakeImportCAEndpoint(s service.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		req := request.(ImportCARequest)

		err = ValidateImportCARequest(req)
		if err != nil {
			valError := errors.ValidationError{
				Msg: err.Error(),
			}
			return nil, &valError
		}

		caType, _ := secrets.ParseCAType(req.CaType)

		data, _ := base64.StdEncoding.DecodeString(req.CaPayload.Crt)
		block, _ := pem.Decode([]byte(data))
		crt, _ := x509.ParseCertificate(block.Bytes)

		privKey := secrets.PrivateKey{}

		privKeyData, _ := base64.StdEncoding.DecodeString(req.CaPayload.PrivateKey)
		privKeyBlock, _ := pem.Decode([]byte(privKeyData))
		ecdsaKey, err := x509.ParseECPrivateKey(privKeyBlock.Bytes)

		if err == nil {
			privKey.Key = ecdsaKey
		} else {
			rsaKey, err := x509.ParsePKCS1PrivateKey(privKeyBlock.Bytes)
			if err == nil {
				privKey.Key = rsaKey
			} else {
				err = &errors.GenericError{
					Message:    "Invalid Key Format",
					StatusCode: 400,
				}
			}
		}

		ca, err := s.ImportCA(ctx, caType, req.CaName, *crt, privKey, req.CaPayload.EnrollerTTL)
		return ca, err
	}
}

func MakeIssuedCertsEndpoint(s service.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		req := request.(CaRequest)
		certs, err := s.GetIssuedCerts(ctx, req.CaType, req.CA)
		return certs, err
	}
}

func MakeCertEndpoint(s service.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		req := request.(GetCertRequest)
		cert, err := s.GetCert(ctx, req.CaType, req.CaName, req.SerialNumber)
		return cert, err
	}
}

func MakeSignCertEndpoint(s service.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		req := request.(SignCertificateRquest)

		err = ValidateSignCertificateRquest(req)
		if err != nil {
			valError := errors.ValidationError{
				Msg: err.Error(),
			}
			return nil, &valError
		}

		data, _ := base64.StdEncoding.DecodeString(req.SignPayload.Csr)
		block, _ := pem.Decode([]byte(data))
		csr, _ := x509.ParseCertificateRequest(block.Bytes)

		caType, _ := secrets.ParseCAType(req.CaType)

		crt, err := s.SignCertificate(ctx, caType, req.CaName, *csr, req.SignPayload.SignVerbatim)
		crtResponse := struct {
			Crt string `json:"crt"`
		}{
			Crt: crt,
		}
		return crtResponse, err
	}
}

func MakeDeleteCertEndpoint(s service.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		req := request.(DeleteCertRequest)
		err = s.DeleteCert(ctx, req.CaType, req.CaName, req.SerialNumber)
		if err != nil {
			return "", err
		} else {
			return "OK", err
		}
	}
}

type HealthRequest struct{}

type HealthResponse struct {
	Healthy bool  `json:"healthy,omitempty"`
	Err     error `json:"-"`
}

type GetCAsRequest struct {
	CaType string
}

type CaRequest struct {
	CaType secrets.CAType

	CA string
}

type DeleteCARequest struct {
	CaType secrets.CAType
	CA     string
}

type GetCertRequest struct {
	CaType       secrets.CAType
	CaName       string
	SerialNumber string
}
type DeleteCertRequest struct {
	CaName       string
	SerialNumber string
	CaType       secrets.CAType
}

type CreateCARequest struct {
	CaType    string `validate:"oneof='pki' 'dmsenroller'"`
	CaName    string `validate:"required"`
	CaPayload struct {
		KeyMetadata struct {
			KeyType string `json:"type" validate:"oneof='rsa' 'ec'"`
			KeyBits int    `json:"bits" validate:"required"`
		} `json:"key_metadata" validate:"required"`

		Subject struct {
			CN string `json:"common_name"`
			O  string `json:"organization"`
			OU string `json:"organization_unit"`
			C  string `json:"country"`
			ST string `json:"state"`
			L  string `json:"locality"`
		} `json:"subject"`

		CaTTL       int `json:"ca_ttl" validate:"required"`
		EnrollerTTL int `json:"enroller_ttl" validate:"gt=0"`
	}
}

func ValidateCreatrCARequest(request CreateCARequest) error {
	CreateCARequestStructLevelValidation := func(sl validator.StructLevel) {
		req := sl.Current().Interface().(CreateCARequest)
		switch req.CaPayload.KeyMetadata.KeyType {
		case "rsa":
			if math.Mod(float64(req.CaPayload.KeyMetadata.KeyBits), 1024) != 0 || req.CaPayload.KeyMetadata.KeyBits < 2048 {
				sl.ReportError(req.CaPayload.KeyMetadata.KeyBits, "bits", "Bits", "bits1024multipleAndGt2048", "")
			}
		case "ec":
			if req.CaPayload.KeyMetadata.KeyBits != 224 && req.CaPayload.KeyMetadata.KeyBits != 256 && req.CaPayload.KeyMetadata.KeyBits != 384 {
				sl.ReportError(req.CaPayload.KeyMetadata.KeyBits, "bits", "Bits", "bitsEcdsaMultiple", "")
			}
		}

		if req.CaPayload.EnrollerTTL >= req.CaPayload.CaTTL {
			sl.ReportError(req.CaPayload.EnrollerTTL, "enrollerttl", "EnrollerTTL", "enrollerTtlGtCaTtl", "")
		}
	}

	validate := validator.New()
	validate.RegisterStructValidation(CreateCARequestStructLevelValidation, CreateCARequest{})
	return validate.Struct(request)
}

type ImportCARequest struct {
	CaType    string `validate:"oneof='pki' 'dmsenroller'"`
	CaName    string `validate:"required"`
	CaPayload struct {
		EnrollerTTL int    `json:"enroller_ttl" validate:"required"`
		Crt         string `json:"crt" validate:"base64"`
		PrivateKey  string `json:"private_key" validate:"base64"`
	}
}

func ValidateImportCARequest(request ImportCARequest) error {
	validate := validator.New()
	return validate.Struct(request)
}

type SignCertificateRquest struct {
	CaType      string `validate:"oneof='pki' 'dmsenroller'"`
	CaName      string `validate:"required"`
	SignPayload struct {
		Csr          string `json:"csr" validate:"base64"`
		SignVerbatim bool   `json:"sign_verbatim"`
	}
}

func ValidateSignCertificateRquest(request SignCertificateRquest) error {
	validate := validator.New()
	return validate.Struct(request)
}
