package api

import (
	"context"
	"fmt"
	"time"

	"github.com/lamassuiot/lamassu-ca/pkg/secrets"

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

func (mw *instrumentingMiddleware) GetCAs(ctx context.Context, caType secrets.CAType) (CAs secrets.Certs, err error) {
	defer func(begin time.Time) {
		lvs := []string{"method", "GetCAs", "error", fmt.Sprint(err != nil)}
		mw.requestCount.With(lvs...).Add(1)
		mw.requestLatency.With(lvs...).Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mw.next.GetCAs(ctx, caType)
}

func (mw *instrumentingMiddleware) CreateCA(ctx context.Context, caName string, ca secrets.Cert) (err error) {
	defer func(begin time.Time) {
		lvs := []string{"method", "CreateCA", "error", fmt.Sprint(err != nil)}
		mw.requestCount.With(lvs...).Add(1)
		mw.requestLatency.With(lvs...).Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mw.next.CreateCA(ctx, caName, ca)
}

func (mw *instrumentingMiddleware) ImportCA(ctx context.Context, caName string, ca secrets.CAImport) (err error) {
	defer func(begin time.Time) {
		lvs := []string{"method", "CreateCA", "error", fmt.Sprint(err != nil)}
		mw.requestCount.With(lvs...).Add(1)
		mw.requestLatency.With(lvs...).Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mw.next.ImportCA(ctx, caName, ca)
}

func (mw *instrumentingMiddleware) DeleteCA(ctx context.Context, CA string) (err error) {
	defer func(begin time.Time) {
		lvs := []string{"method", "DeleteCA", "error", fmt.Sprint(err != nil)}
		mw.requestCount.With(lvs...).Add(1)
		mw.requestLatency.With(lvs...).Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mw.next.DeleteCA(ctx, CA)
}

func (mw *instrumentingMiddleware) GetIssuedCerts(ctx context.Context, caName string, caType secrets.CAType) (certs secrets.Certs, err error) {
	defer func(begin time.Time) {
		lvs := []string{"method", "GetIssuedCerts", "error", fmt.Sprint(err != nil)}
		mw.requestCount.With(lvs...).Add(1)
		mw.requestLatency.With(lvs...).Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mw.next.GetIssuedCerts(ctx, caName, caType)
}
func (mw *instrumentingMiddleware) GetCert(ctx context.Context, caName string, serialNumber string) (cert secrets.Cert, err error) {
	defer func(begin time.Time) {
		lvs := []string{"method", "GetCert", "error", fmt.Sprint(err != nil)}
		mw.requestCount.With(lvs...).Add(1)
		mw.requestLatency.With(lvs...).Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mw.next.GetCert(ctx, caName, serialNumber)
}

func (mw *instrumentingMiddleware) DeleteCert(ctx context.Context, caName string, serialNumber string) (err error) {
	defer func(begin time.Time) {
		lvs := []string{"method", "DeleteCert", "error", fmt.Sprint(err != nil)}
		mw.requestCount.With(lvs...).Add(1)
		mw.requestLatency.With(lvs...).Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mw.next.DeleteCert(ctx, caName, serialNumber)
}
