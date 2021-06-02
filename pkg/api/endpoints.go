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
	GetCAsEndpoint         endpoint.Endpoint
	CreateCAEndpoint       endpoint.Endpoint
	ImportCAEndpoint       endpoint.Endpoint
	DeleteCAEndpoint       endpoint.Endpoint
	GetIssuedCertsEndpoint endpoint.Endpoint
}

func MakeServerEndpoints(s Service, otTracer stdopentracing.Tracer) Endpoints {
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
	return Endpoints{
		HealthEndpoint:         healthEndpoint,
		GetCAsEndpoint:         getCAsEndpoint,
		CreateCAEndpoint:       createCAEndpoint,
		ImportCAEndpoint:       importCAEndpoint,
		DeleteCAEndpoint:       deleteCAEndpoint,
		GetIssuedCertsEndpoint: getIssuedCertsEndpoint,
	}
}

func MakeHealthEndpoint(s Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		healthy := s.Health(ctx)
		return HealthResponse{Healthy: healthy}, nil
	}
}

func MakeGetCAsEndpoint(s Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		_ = request.(getCAsRequest)
		CAs, err := s.GetCAs(ctx)
		return CAs.Certs, err
	}
}

func MakeCreateCAEndpoint(s Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		req := request.(createCARequest)
		err = s.CreateCA(ctx, req.CAName, req.CA)
		return createCAResponse{Err: err}, nil
	}
}

func MakeDeleteCAEndpoint(s Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		req := request.(deleteCARequest)
		err = s.DeleteCA(ctx, req.CA)
		return deleteCAResponse{Err: err}, nil
	}
}

func MakeImportCAEndpoint(s Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		req := request.(importCARequest)
		err = s.ImportCA(ctx, req.CAName, req.CAImport)
		return deleteCAResponse{Err: err}, nil
	}
}

func MakeIssuedCertsEndpoint(s Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		if request != nil {
			req := request.(caRequest)
			certs, err := s.GetIssuedCerts(ctx, req.CA)
			return certs.Certs, err
		} else {
			certs, err := s.GetIssuedCerts(ctx, "")
			return certs.Certs, err
		}
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

type caRequest struct {
	CA string
}

type deleteCARequest struct {
	CA string
}

type createCARequest struct {
	CAName string
	CA     secrets.Cert
}
type importCARequest struct {
	CAName   string
	CAImport secrets.CAImport
}
type createCAResponse struct {
	Err error `json:"-"`
}
type importCAResponse struct {
	Err error `json:"-"`
}

type deleteCAResponse struct {
	Err error `json:"-"`
}

func (r deleteCAResponse) error() error { return r.Err }
