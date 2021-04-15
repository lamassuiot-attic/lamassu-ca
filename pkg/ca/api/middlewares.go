package api

import (
	"context"
	"time"

	"github.com/lamassuiot/enroller/pkg/ca/secrets"

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

func (mw loggingMiddleware) GetCAs(ctx context.Context) (CAs secrets.CAs, err error) {
	defer func(begin time.Time) {
		mw.logger.Log(
			"method", "GetCAs",
			"number_cas", len(CAs.CAs),
			"took", time.Since(begin),
			"err", err,
		)
	}(time.Now())
	return mw.next.GetCAs(ctx)
}

func (mw loggingMiddleware) GetCAInfo(ctx context.Context, CA string) (CAInfo secrets.CAInfo, err error) {
	defer func(begin time.Time) {
		mw.logger.Log(
			"method", "GetCAInfo",
			"ca_name", CA,
			"cn", CAInfo.CN,
			"key_type", CAInfo.KeyType,
			"key_bits", CAInfo.KeyBits,
			"took", time.Since(begin),
			"err", err,
		)
	}(time.Now())
	return mw.next.GetCAInfo(ctx, CA)
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
