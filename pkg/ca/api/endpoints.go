package api

import (
	"context"

	"github.com/lamassuiot/enroller/pkg/ca/secrets"

	"github.com/go-kit/kit/endpoint"
	"github.com/go-kit/kit/tracing/opentracing"
	stdopentracing "github.com/opentracing/opentracing-go"
)

type Endpoints struct {
	HealthEndpoint    endpoint.Endpoint
	GetCAsEndpoint    endpoint.Endpoint
	GetCAInfoEndpoint endpoint.Endpoint
	DeleteCAEndpoint  endpoint.Endpoint
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

	var getCAInfoEndpoint endpoint.Endpoint
	{
		getCAInfoEndpoint = MakeGetCAInfoEndpoint(s)
		getCAInfoEndpoint = opentracing.TraceServer(otTracer, "GetCAInfo")(getCAInfoEndpoint)
	}

	var deleteCAEndpoint endpoint.Endpoint
	{
		deleteCAEndpoint = MakeDeleteCAEndpoint(s)
		deleteCAEndpoint = opentracing.TraceServer(otTracer, "DeleteCA")(deleteCAEndpoint)
	}
	return Endpoints{
		HealthEndpoint:    healthEndpoint,
		GetCAsEndpoint:    getCAsEndpoint,
		GetCAInfoEndpoint: getCAInfoEndpoint,
		DeleteCAEndpoint:  deleteCAEndpoint,
	}
}

func MakeHealthEndpoint(s Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		healthy := s.Health(ctx)
		return healthResponse{Healthy: healthy}, nil
	}
}

func MakeGetCAsEndpoint(s Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		_ = request.(getCAsRequest)
		CAs, err := s.GetCAs(ctx)
		return getCAsResponse{CAs: CAs, Err: err}, nil
	}
}

func MakeGetCAInfoEndpoint(s Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		req := request.(getCAInfoRequest)
		CAInfo, err := s.GetCAInfo(ctx, req.CA)
		return getCAInfoResponse{CAInfo: CAInfo, Err: err}, nil
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

type healthResponse struct {
	Healthy bool  `json:"healthy,omitempty"`
	Err     error `json:"err,omitempty"`
}

type getCAsRequest struct{}

type getCAsResponse struct {
	CAs secrets.CAs
	Err error
}

func (r getCAsResponse) error() error { return r.Err }

type getCAInfoRequest struct {
	CA string
}

type getCAInfoResponse struct {
	CAInfo secrets.CAInfo
	Err    error
}

func (r getCAInfoResponse) error() error { return r.Err }

type deleteCARequest struct {
	CA string
}

type deleteCAResponse struct {
	Err error
}

func (r deleteCAResponse) error() error { return r.Err }
