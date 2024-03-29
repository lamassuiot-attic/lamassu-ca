package api

import (
	"context"

	"github.com/lamassuiot/lamassu-ca/pkg/secrets"

	"github.com/go-kit/kit/endpoint"
	"github.com/go-kit/kit/tracing/opentracing"
	stdopentracing "github.com/opentracing/opentracing-go"
)

type Endpoints struct {
	HealthEndpoint         endpoint.Endpoint
	GetAllCAsEndpoint      endpoint.Endpoint
	GetOpsCAsEndpoint      endpoint.Endpoint
	GetSystemCAsEndpoint   endpoint.Endpoint
	CreateCAEndpoint       endpoint.Endpoint
	ImportCAEndpoint       endpoint.Endpoint
	DeleteCAEndpoint       endpoint.Endpoint
	GetIssuedCertsEndpoint endpoint.Endpoint
	GetCertEndpoint        endpoint.Endpoint
	DeleteCertEndpoint     endpoint.Endpoint
}

func MakeServerEndpoints(s Service, otTracer stdopentracing.Tracer) Endpoints {
	var healthEndpoint endpoint.Endpoint
	{
		healthEndpoint = MakeHealthEndpoint(s)
		healthEndpoint = opentracing.TraceServer(otTracer, "Health")(healthEndpoint)
	}
	var getAllCAsEndpoint endpoint.Endpoint
	{
		getAllCAsEndpoint = MakeGetAllCAsEndpoint(s)
		getAllCAsEndpoint = opentracing.TraceServer(otTracer, "GetCAs")(getAllCAsEndpoint)
	}
	var getOpsCAsEndpoint endpoint.Endpoint
	{
		getOpsCAsEndpoint = MakeGetOpsCAsEndpoint(s)
		getOpsCAsEndpoint = opentracing.TraceServer(otTracer, "GetCAs")(getOpsCAsEndpoint)
	}
	var getSystemCAsEndpoint endpoint.Endpoint
	{
		getSystemCAsEndpoint = MakeGetSystemCAsEndpoint(s)
		getSystemCAsEndpoint = opentracing.TraceServer(otTracer, "GetCAs")(getSystemCAsEndpoint)
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

	var deleteCertEndpoint endpoint.Endpoint
	{
		deleteCertEndpoint = MakeDeleteCertEndpoint(s)
		deleteCertEndpoint = opentracing.TraceServer(otTracer, "DeleteCert")(deleteCertEndpoint)
	}
	return Endpoints{
		HealthEndpoint:         healthEndpoint,
		GetAllCAsEndpoint:      getAllCAsEndpoint,
		GetOpsCAsEndpoint:      getOpsCAsEndpoint,
		GetSystemCAsEndpoint:   getSystemCAsEndpoint,
		CreateCAEndpoint:       createCAEndpoint,
		ImportCAEndpoint:       importCAEndpoint,
		DeleteCAEndpoint:       deleteCAEndpoint,
		GetIssuedCertsEndpoint: getIssuedCertsEndpoint,
		GetCertEndpoint:        getCertEndpoint,
		DeleteCertEndpoint:     deleteCertEndpoint,
	}
}

func MakeHealthEndpoint(s Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		healthy := s.Health(ctx)
		return HealthResponse{Healthy: healthy}, nil
	}
}

func MakeGetAllCAsEndpoint(s Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		_ = request.(getCAsRequest)
		CAs, err := s.GetCAs(ctx, secrets.AllCAs)
		return CAs.Certs, err
	}
}
func MakeGetSystemCAsEndpoint(s Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		_ = request.(getCAsRequest)
		CAs, err := s.GetCAs(ctx, secrets.SystemCAs)
		return CAs.Certs, err
	}
}

func MakeGetOpsCAsEndpoint(s Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		_ = request.(getCAsRequest)
		CAs, err := s.GetCAs(ctx, secrets.OperationsCAs)
		return CAs.Certs, err
	}
}

func MakeCreateCAEndpoint(s Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		req := request.(CreateCARequest)
		err = s.CreateCA(ctx, req.CAName, req.CA)
		return nil, err
	}
}

func MakeDeleteCAEndpoint(s Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		req := request.(DeleteCARequest)
		err = s.DeleteCA(ctx, req.CA)
		return errorResponse{Err: err}, nil
	}
}

func MakeImportCAEndpoint(s Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		req := request.(ImportCARequest)
		err = s.ImportCA(ctx, req.CAName, req.CAImport)
		return errorResponse{Err: err}, nil
	}
}

func MakeIssuedCertsEndpoint(s Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		req := request.(CaRequest)
		certs, err := s.GetIssuedCerts(ctx, req.CA, req.caType)
		return certs.Certs, err
	}
}

func MakeCertEndpoint(s Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		req := request.(GetCertRequest)
		cert, err := s.GetCert(ctx, req.CaName, req.SerialNumber)
		return cert, err
	}
}
func MakeDeleteCertEndpoint(s Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		req := request.(DeleteCertRequest)
		err = s.DeleteCert(ctx, req.CaName, req.SerialNumber)
		return errorResponse{Err: err}, nil
	}
}

type healthRequest struct{}

type HealthResponse struct {
	Healthy bool  `json:"healthy,omitempty"`
	Err     error `json:"-"`
}

type getCAsRequest struct{}

type GetCAsResponse struct {
	CAs secrets.Certs
	Err error `json:"-"`
}

func (r GetCAsResponse) error() error { return r.Err }

type CaRequest struct {
	CA     string
	caType secrets.CAType
}

type DeleteCARequest struct {
	CA string
}

type GetCertRequest struct {
	CaName       string
	SerialNumber string
}
type DeleteCertRequest struct {
	CaName       string
	SerialNumber string
}

type CreateCARequest struct {
	CAName string
	CA     secrets.Cert
}
type ImportCARequest struct {
	CAName   string
	CAImport secrets.CAImport
}

type errorResponse struct {
	Err error `json:"-"`
}

func (r errorResponse) error() error { return r.Err }
