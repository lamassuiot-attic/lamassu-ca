package api

import (
	"context"
	"time"

	"github.com/lamassuiot/lamassu-ca/pkg/secrets"

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

func (mw loggingMiddleware) Health(ctx context.Context) (healthy bool) {
	defer func(begin time.Time) {
		mw.logger.Log(
			"method", "Health",
			"took", time.Since(begin),
			"healthy", healthy,
		)
	}(time.Now())
	return mw.next.Health(ctx)
}

func (mw loggingMiddleware) GetCAs(ctx context.Context) (CAs secrets.Certs, err error) {
	defer func(begin time.Time) {
		mw.logger.Log(
			"method", "GetCAs",
			"number_cas", len(CAs.Certs),
			"took", time.Since(begin),
			"err", err,
		)
	}(time.Now())
	return mw.next.GetCAs(ctx)
}

func (mw loggingMiddleware) CreateCA(ctx context.Context, caName string, ca secrets.Cert) (err error) {
	defer func(begin time.Time) {
		mw.logger.Log(
			"method", "CreateCA",
			"ca_name", caName,
			"ca_info", ca,
			"err", err,
		)
	}(time.Now())
	return mw.next.CreateCA(ctx, caName, ca)
}

func (mw loggingMiddleware) ImportCA(ctx context.Context, caName string, ca secrets.CAImport) (err error) {
	defer func(begin time.Time) {
		mw.logger.Log(
			"method", "CreateCA",
			"ca_name", caName,
			//"ca_bundle", ca, // THIS CAN BE A SECURITY FLAW
			"err", err,
		)
	}(time.Now())
	return mw.next.ImportCA(ctx, caName, ca)
}

func (mw loggingMiddleware) DeleteCA(ctx context.Context, CA string) (err error) {
	defer func(begin time.Time) {
		mw.logger.Log(
			"method", "DeleteCA",
			"ca_name", CA,
			"took", time.Since(begin),
			"err", err,
		)
	}(time.Now())
	return mw.next.DeleteCA(ctx, CA)
}

func (mw loggingMiddleware) GetIssuedCerts(ctx context.Context, CA string) (certs secrets.Certs, err error) {
	defer func(begin time.Time) {
		mw.logger.Log(
			"method", "GetIssuedCerts",
			"ca_name", CA,
			"number_issued_certs", len(certs.Certs),
			"took", time.Since(begin),
			"err", err,
		)
	}(time.Now())
	return mw.next.GetIssuedCerts(ctx, CA)
}
