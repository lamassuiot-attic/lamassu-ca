package api

import (
	"context"

	"github.com/lamassuiot/lamassu-ca/pkg/secrets"

	"github.com/go-kit/kit/endpoint"
	"github.com/go-kit/kit/tracing/opentracing"
	stdopentracing "github.com/opentracing/opentracing-go"
)

type Endpoints struct {
	HealthEndpoint   endpoint.Endpoint
	GetCAsEndpoint   endpoint.Endpoint
	GetCACrtEndpoint endpoint.Endpoint
	CreateCAEndpoint endpoint.Endpoint
	DeleteCAEndpoint endpoint.Endpoint
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

	var getCACrtEndpoint endpoint.Endpoint
	{
		getCACrtEndpoint = MakeGetCACrtEndpoint(s)
		getCACrtEndpoint = opentracing.TraceServer(otTracer, "GetCACrt")(getCACrtEndpoint)
	}

	var createCAEndpoint endpoint.Endpoint
	{
		createCAEndpoint = MakeCreateCAEndpoint(s)
		createCAEndpoint = opentracing.TraceServer(otTracer, "CreateCA")(createCAEndpoint)
	}

	var deleteCAEndpoint endpoint.Endpoint
	{
		deleteCAEndpoint = MakeDeleteCAEndpoint(s)
		deleteCAEndpoint = opentracing.TraceServer(otTracer, "DeleteCA")(deleteCAEndpoint)
	}
	return Endpoints{
		HealthEndpoint:   healthEndpoint,
		GetCAsEndpoint:   getCAsEndpoint,
		GetCACrtEndpoint: getCACrtEndpoint,
		CreateCAEndpoint: createCAEndpoint,
		DeleteCAEndpoint: deleteCAEndpoint,
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
		return CAs.CAs, err
	}
}

func MakeGetCACrtEndpoint(s Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		req := request.(getCACrtRequest)
		caCrt, err := s.GetCACrt(ctx, req.CA)
		return caCrt, err
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

type healthRequest struct{}

type HealthResponse struct {
	Healthy bool  `json:"healthy,omitempty"`
	Err     error `json:"-"`
}

type getCAsRequest struct{}

type GetCAsResponse struct {
	CAs secrets.CAs
	Err error `json:"-"`
}

func (r GetCAsResponse) error() error { return r.Err }

type getCACrtRequest struct {
	CA string
}

type GetCACrtResponse struct {
	CACrt secrets.CACrt
	Err   error `json:"-"`
}

func (r GetCACrtResponse) error() error { return r.Err }

type deleteCARequest struct {
	CA string
}

type createCARequest struct {
	CAName string
	CA     secrets.CA
}
type createCAResponse struct {
	Err error `json:"-"`
}

type deleteCAResponse struct {
	Err error `json:"-"`
}

func (r deleteCAResponse) error() error { return r.Err }
