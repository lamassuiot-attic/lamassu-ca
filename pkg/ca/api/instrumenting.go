package api

import (
	"context"
	"fmt"
	"time"

	"github.com/lamassuiot/enroller/pkg/ca/secrets"

	"github.com/go-kit/kit/metrics"
)

type instrumentingMiddleware struct {
	requestCount   metrics.Counter
	requestLatency metrics.Histogram
	next           Service
}

func NewInstrumentingMiddleware(counter metrics.Counter, latency metrics.Histogram) Middleware {
	return func(next Service) Service {
		return &instrumentingMiddleware{
			requestCount:   counter,
			requestLatency: latency,
			next:           next,
		}
	}
}

func (mw *instrumentingMiddleware) Health(ctx context.Context) bool {
	defer func(begin time.Time) {
		lvs := []string{"method", "Health", "error", "false"}
		mw.requestCount.With(lvs...).Add(1)
		mw.requestLatency.With(lvs...).Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mw.next.Health(ctx)
}

func (mw *instrumentingMiddleware) GetCAs(ctx context.Context) (CAs secrets.CAs, err error) {
	defer func(begin time.Time) {
		lvs := []string{"method", "GetCAs", "error", fmt.Sprint(err != nil)}
		mw.requestCount.With(lvs...).Add(1)
		mw.requestLatency.With(lvs...).Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mw.next.GetCAs(ctx)
}

func (mw *instrumentingMiddleware) GetCAInfo(ctx context.Context, CA string) (CAInfo secrets.CAInfo, err error) {
	defer func(begin time.Time) {
		lvs := []string{"method", "GetCAInfo", "error", fmt.Sprint(err != nil)}
		mw.requestCount.With(lvs...).Add(1)
		mw.requestLatency.With(lvs...).Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mw.next.GetCAInfo(ctx, CA)
}

func (mw *instrumentingMiddleware) DeleteCA(ctx context.Context, CA string) (err error) {
	defer func(begin time.Time) {
		lvs := []string{"method", "DeleteCA", "error", fmt.Sprint(err != nil)}
		mw.requestCount.With(lvs...).Add(1)
		mw.requestLatency.With(lvs...).Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mw.next.DeleteCA(ctx, CA)
}
