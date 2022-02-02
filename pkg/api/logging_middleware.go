package api

import (
	"context"
	"crypto/x509"
	"time"

	"github.com/lamassuiot/lamassu-ca/pkg/secrets"
	"github.com/opentracing/opentracing-go"

	"github.com/go-kit/kit/log"
)

type Middleware func(Service) Service

func LoggingMiddleware(logger log.Logger) Middleware {
	return func(next Service) Service {
		return &loggingMiddleware{
			next:   next,
			logger: logger,
		}
	}
}

type loggingMiddleware struct {
	next   Service
	logger log.Logger
}

func (mw loggingMiddleware) GetSecretProviderName(ctx context.Context) (providerName string) {

	defer func(begin time.Time) {
		mw.logger.Log(
			"method", "GetSecretProviderName",
			"took", time.Since(begin),
			"provider_name", providerName,
			"trace_id", opentracing.SpanFromContext(ctx),
		)
	}(time.Now())
	return mw.next.GetSecretProviderName(ctx)
}

func (mw loggingMiddleware) Health(ctx context.Context) (healthy bool) {
	defer func(begin time.Time) {
		mw.logger.Log(
			"method", "Health",
			"took", time.Since(begin),
			"healthy", healthy,
			"trace_id", opentracing.SpanFromContext(ctx),
		)
	}(time.Now())
	return mw.next.Health(ctx)
}

func (mw loggingMiddleware) GetCAs(ctx context.Context, caType secrets.CAType) (CAs secrets.Certs, err error) {
	defer func(begin time.Time) {
		mw.logger.Log(
			"method", "GetCAs",
			"number_cas", len(CAs.Certs),
			"ca_type", caType,
			"took", time.Since(begin),
			"err", err,
			"trace_id", opentracing.SpanFromContext(ctx),
		)
	}(time.Now())
	return mw.next.GetCAs(ctx, caType)
}

func (mw loggingMiddleware) CreateCA(ctx context.Context, caType secrets.CAType, caName string, ca secrets.Cert) (cretedCa secrets.Cert, err error) {
	defer func(begin time.Time) {
		mw.logger.Log(
			"method", "CreateCA",
			"ca_name", caName,
			"ca_type", caType,
			"ca_info", ca,
			"creted_ca", cretedCa,
			"err", err,
			"trace_id", opentracing.SpanFromContext(ctx),
		)
	}(time.Now())
	return mw.next.CreateCA(ctx, caType, caName, ca)
}

func (mw loggingMiddleware) ImportCA(ctx context.Context, caType secrets.CAType, caName string, ca secrets.CAImport) (err error) {
	defer func(begin time.Time) {
		mw.logger.Log(
			"method", "CreateCA",
			"ca_name", caName,
			"ca_type", caType,
			"trace_id", opentracing.SpanFromContext(ctx),
			"err", err,
		)
	}(time.Now())
	return mw.next.ImportCA(ctx, caType, caName, ca)
}

func (mw loggingMiddleware) DeleteCA(ctx context.Context, caType secrets.CAType, CA string) (err error) {
	defer func(begin time.Time) {
		mw.logger.Log(
			"method", "DeleteCA",
			"ca_name", CA,
			"ca_type", caType,
			"took", time.Since(begin),
			"trace_id", opentracing.SpanFromContext(ctx),
			"err", err,
		)
	}(time.Now())
	return mw.next.DeleteCA(ctx, caType, CA)
}

func (mw loggingMiddleware) GetIssuedCerts(ctx context.Context, caType secrets.CAType, CA string) (certs secrets.Certs, err error) {
	defer func(begin time.Time) {
		mw.logger.Log(
			"method", "GetIssuedCerts",
			"ca_name", CA,
			"number_issued_certs", len(certs.Certs),
			"took", time.Since(begin),
			"trace_id", opentracing.SpanFromContext(ctx),
			"err", err,
		)
	}(time.Now())
	return mw.next.GetIssuedCerts(ctx, caType, CA)
}
func (mw loggingMiddleware) GetCert(ctx context.Context, caType secrets.CAType, caName string, serialNumber string) (cert secrets.Cert, err error) {
	defer func(begin time.Time) {
		mw.logger.Log(
			"method", "GetCert",
			"ca_name", caName,
			"serialNumber", serialNumber,
			"cert", cert,
			"took", time.Since(begin),
			"trace_id", opentracing.SpanFromContext(ctx),
			"err", err,
		)
	}(time.Now())
	return mw.next.GetCert(ctx, caType, caName, serialNumber)
}

func (mw loggingMiddleware) DeleteCert(ctx context.Context, caType secrets.CAType, caName string, serialNumber string) (err error) {
	defer func(begin time.Time) {
		mw.logger.Log(
			"method", "DeleteCert",
			"ca_name", caName,
			"serialNumber", serialNumber,
			"took", time.Since(begin),
			"trace_id", opentracing.SpanFromContext(ctx),
			"err", err,
		)
	}(time.Now())
	return mw.next.DeleteCert(ctx, caType, caName, serialNumber)
}

func (mw loggingMiddleware) SignCertificate(ctx context.Context, caType secrets.CAType, caName string, csr x509.CertificateRequest) (crt string, err error) {
	defer func(begin time.Time) {
		mw.logger.Log(
			"method", "SignCertificate",
			"ca_name", caName,
			"ca_type", caType,
			"csr", csr,
			"crt", crt,
			"took", time.Since(begin),
			"trace_id", opentracing.SpanFromContext(ctx),
			"err", err,
		)
	}(time.Now())
	return mw.next.SignCertificate(ctx, caType, caName, csr)
}