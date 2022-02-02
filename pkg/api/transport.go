package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/lamassuiot/lamassu-ca/pkg/secrets"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/tracing/opentracing"

	"github.com/go-kit/kit/auth/jwt"
	"github.com/go-kit/kit/transport"
	httptransport "github.com/go-kit/kit/transport/http"

	stdopentracing "github.com/opentracing/opentracing-go"
)

type errorer interface {
	error() error
}

var (
	errCAName = errors.New("CA name not provided")
	errCAType = errors.New("CA type not provided")
	errSerial = errors.New("Serial Number not provided")
)

type contextKey string

const (
	LamassuLoggerContextkey contextKey = "LamassuLogger"
)

func HTTPToContext(logger log.Logger) httptransport.RequestFunc {
	return func(ctx context.Context, req *http.Request) context.Context {
		// Try to join to a trace propagated in `req`.
		logger := log.With(logger, "span_id", stdopentracing.SpanFromContext(ctx))
		return context.WithValue(ctx, LamassuLoggerContextkey, logger)
	}
}

func MakeHTTPHandler(s Service, logger log.Logger, otTracer stdopentracing.Tracer) http.Handler {
	r := mux.NewRouter()
	e := MakeServerEndpoints(s, otTracer)
	options := []httptransport.ServerOption{
		httptransport.ServerBefore(HTTPToContext(logger)),
		httptransport.ServerErrorHandler(transport.NewLogErrorHandler(logger)),
		httptransport.ServerErrorEncoder(encodeError),
		httptransport.ServerBefore(jwt.HTTPToContext()),
	}

	r.Methods("GET").Path("/v1/health").Handler(httptransport.NewServer(
		e.HealthEndpoint,
		decodeHealthRequest,
		encodeResponse,
		append(
			options,
			httptransport.ServerBefore(opentracing.HTTPToContext(otTracer, "Health", logger)),
			httptransport.ServerBefore(HTTPToContext(logger)),
		)...,
	))

	// Get all CAs
	r.Methods("GET").Path("/v1/{caType}").Handler(httptransport.NewServer(
		e.GetCAsEndpoint,
		decodeGetCAsRequest,
		encodeResponse,
		append(
			options,
			httptransport.ServerBefore(opentracing.HTTPToContext(otTracer, "GetCAs", logger)),
			httptransport.ServerBefore(HTTPToContext(logger)),
		)...,
	))

	// Create new CA using Form
	r.Methods("POST").Path("/v1/pki/{ca}").Handler(httptransport.NewServer(
		e.CreateCAEndpoint,
		decodeCreateCARequest,
		encodeResponse,
		append(
			options,
			httptransport.ServerBefore(opentracing.HTTPToContext(otTracer, "CreateCA", logger)),
			httptransport.ServerBefore(HTTPToContext(logger)),
		)...,
	))

	// Import existing crt and key
	r.Methods("POST").Path("/v1/pki/import/{ca}").Handler(httptransport.NewServer(
		e.ImportCAEndpoint,
		decodeImportCARequest,
		encodeResponse,
		append(
			options,
			httptransport.ServerBefore(opentracing.HTTPToContext(otTracer, "ImportCA", logger)),
			httptransport.ServerBefore(HTTPToContext(logger)),
		)...,
	))

	// Revoke CA
	r.Methods("DELETE").Path("/v1/pki/{ca}").Handler(httptransport.NewServer(
		e.DeleteCAEndpoint,
		decodeDeleteCARequest,
		encodeResponse,
		append(
			options,
			httptransport.ServerBefore(opentracing.HTTPToContext(otTracer, "DeleteCA", logger)),
			httptransport.ServerBefore(HTTPToContext(logger)),
		)...,
	))

	// Get Issued certificates by {ca}
	r.Methods("GET").Path("/v1/{caType}/{ca}/issued").Handler(httptransport.NewServer(
		e.GetIssuedCertsEndpoint,
		decodeGetIssuedCertsRequest,
		encodeResponse,
		append(
			options,
			httptransport.ServerBefore(opentracing.HTTPToContext(otTracer, "GetIssuedCerts", logger)),
			httptransport.ServerBefore(HTTPToContext(logger)),
		)...,
	))

	// Get certificate by {ca} and {serialNumber}
	r.Methods("GET").Path("/v1/{caType}/{ca}/cert/{serialNumber}").Handler(httptransport.NewServer(
		e.GetCertEndpoint,
		decodeGetCertRequest,
		encodeResponse,
		append(
			options,
			httptransport.ServerBefore(opentracing.HTTPToContext(otTracer, "GetCert", logger)),
			httptransport.ServerBefore(HTTPToContext(logger)),
		)...,
	))

	// Sign CSR by {ca}
	r.Methods("POST").Path("/v1/{caType}/{ca}/sign").Handler(httptransport.NewServer(
		e.SignCertEndpoint,
		decodeSignCertificateRequest,
		encodeResponse,
		append(
			options,
			httptransport.ServerBefore(opentracing.HTTPToContext(otTracer, "SignCSR", logger)),
			httptransport.ServerBefore(HTTPToContext(logger)),
		)...,
	))

	// Revoke certificate issued by {ca} and {serialNumber}
	r.Methods("DELETE").Path("/v1/{caType}/{ca}/cert/{serialNumber}").Handler(httptransport.NewServer(
		e.DeleteCertEndpoint,
		decodeDeleteCertRequest,
		encodeResponse,
		append(
			options,
			httptransport.ServerBefore(opentracing.HTTPToContext(otTracer, "DeleteCert", logger)),
			httptransport.ServerBefore(HTTPToContext(logger)),
		)...,
	))

	return r
}

func decodeHealthRequest(ctx context.Context, r *http.Request) (request interface{}, err error) {
	var req healthRequest
	return req, nil
}

func decodeGetCAsRequest(ctx context.Context, r *http.Request) (request interface{}, err error) {
	vars := mux.Vars(r)
	caTypeString, ok := vars["caType"]
	if !ok {
		return nil, errCAType
	}
	if caTypeString == "pki" {
		var req GetCAsRequest = GetCAsRequest{
			CaType: secrets.Pki,
		}
		return req, nil
	} else {
		var req GetCAsRequest = GetCAsRequest{
			CaType: secrets.DmsEnroller,
		}
		return req, nil
	}

}

func decodeGetIssuedCertsRequest(ctx context.Context, r *http.Request) (request interface{}, err error) {
	vars := mux.Vars(r)
	CA, ok := vars["ca"]
	if !ok {
		return nil, errCAName
	}
	caTypeString, ok := vars["caType"]
	if !ok {
		return nil, errCAType
	}

	caType, err := secrets.ParseCAType(caTypeString)
	if err != nil {
		return nil, err
	}
	return CaRequest{
		CaType: caType,
		CA:     CA,
	}, nil
}

func decodeCreateCARequest(ctx context.Context, r *http.Request) (request interface{}, err error) {
	vars := mux.Vars(r)
	var caRequestInfo secrets.Cert
	json.NewDecoder(r.Body).Decode(&caRequestInfo)
	if err != nil {
		return nil, errors.New("Cannot decode JSON request")
	}

	caName, ok := vars["ca"]
	if !ok {
		return nil, errCAName
	}
	return CreateCARequest{
		CaType: secrets.Pki,
		CAName: caName,
		CA:     caRequestInfo,
	}, nil
}

func decodeImportCARequest(ctx context.Context, r *http.Request) (request interface{}, err error) {
	vars := mux.Vars(r)
	var importCaRequest secrets.CAImport
	json.NewDecoder(r.Body).Decode(&importCaRequest)
	if err != nil {
		return nil, errors.New("Cannot decode JSON request")
	}

	caName, ok := vars["ca"]
	if !ok {
		return nil, errCAName
	}
	return ImportCARequest{
		CaType:   secrets.Pki,
		CAName:   caName,
		CAImport: importCaRequest,
	}, nil
}

func decodeDeleteCARequest(ctx context.Context, r *http.Request) (request interface{}, err error) {
	vars := mux.Vars(r)
	CA, ok := vars["ca"]
	if !ok {
		return nil, errCAName
	}
	return DeleteCARequest{
		CaType: secrets.Pki,
		CA:     CA,
	}, nil
}

func decodeGetCertRequest(ctx context.Context, r *http.Request) (request interface{}, err error) {
	vars := mux.Vars(r)
	CA, ok := vars["ca"]
	if !ok {
		return nil, errCAName
	}
	caTypeString, ok := vars["caType"]
	if !ok {
		return nil, errCAType
	}

	caType, err := secrets.ParseCAType(caTypeString)
	if err != nil {
		return nil, err
	}
	serialNumber, ok := vars["serialNumber"]
	if !ok {
		return nil, errSerial
	}
	return GetCertRequest{
		CaType:       caType,
		CaName:       CA,
		SerialNumber: serialNumber,
	}, nil
}

func decodeSignCertificateRequest(ctx context.Context, r *http.Request) (request interface{}, err error) {
	vars := mux.Vars(r)
	CA, ok := vars["ca"]
	if !ok {
		return nil, errCAName
	}
	caTypeString, ok := vars["caType"]
	if !ok {
		return nil, errCAType
	}

	caType, err := secrets.ParseCAType(caTypeString)
	if err != nil {
		return nil, err
	}

	type Csr struct {
		Csr string `json:"csr"`
	}

	var csrRequest Csr
	json.NewDecoder(r.Body).Decode(&csrRequest)
	if err != nil {
		return nil, errors.New("Cannot decode JSON request")
	}

	return SignCertificateRquest{
		CaType:    caType,
		CAName:    CA,
		base64Csr: csrRequest.Csr,
	}, nil
}

func decodeDeleteCertRequest(ctx context.Context, r *http.Request) (request interface{}, err error) {
	vars := mux.Vars(r)
	ca, ok := vars["ca"]
	if !ok {
		return nil, errCAName
	}
	caTypeString, ok := vars["caType"]
	if !ok {
		return nil, errCAType
	}

	caType, err := secrets.ParseCAType(caTypeString)
	if err != nil {
		return nil, err
	}

	if !ok {
		return nil, errCAName
	}
	serialNumber, ok := vars["serialNumber"]
	if !ok {
		return nil, errSerial
	}
	return DeleteCertRequest{
		CaType:       caType,
		CaName:       ca,
		SerialNumber: serialNumber,
	}, nil
}

func encodeResponse(ctx context.Context, w http.ResponseWriter, response interface{}) error {
	if e, ok := response.(errorer); ok && e.error() != nil {
		// Not a Go kit transport error, but a business-logic error.
		// Provide those as HTTP errors.

		// https://medium.com/@ozdemir.zynl/rest-api-error-handling-in-go-behavioral-type-assertion-509d93636afd
		//
		encodeError(ctx, e.error(), w)

		return nil
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	return json.NewEncoder(w).Encode(response)
}

func encodeError(_ context.Context, err error, w http.ResponseWriter) {
	/*if err == nil {
		panic("encodeError with nil error")
	}*/
	//http.Error(w, err.Error(), codeFrom(err))
	w.WriteHeader(codeFrom(err))
	json.NewEncoder(w).Encode(errorWrapper{Error: err.Error()})

}

type errorWrapper struct {
	Error string `json:"error"`
}

func codeFrom(err error) int {
	switch err {
	case ErrGetCAs:
		return http.StatusBadRequest
	default:
		return http.StatusInternalServerError
	}
}
