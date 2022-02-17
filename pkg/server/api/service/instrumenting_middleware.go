package service

import (
	"context"
	"crypto/x509"
	"fmt"
	"time"

	"github.com/lamassuiot/lamassu-ca/pkg/server/secrets"

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

func (mw *instrumentingMiddleware) GetSecretProviderName(ctx context.Context) (providerName string) {
	defer func(begin time.Time) {
		lvs := []string{"method", "GetSecretProviderName", "error", "false"}
		mw.requestCount.With(lvs...).Add(1)
		mw.requestLatency.With(lvs...).Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mw.next.GetSecretProviderName(ctx)
}

func (mw *instrumentingMiddleware) Health(ctx context.Context) bool {
	defer func(begin time.Time) {
		lvs := []string{"method", "Health", "error", "false"}
		mw.requestCount.With(lvs...).Add(1)
		mw.requestLatency.With(lvs...).Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mw.next.Health(ctx)
}

func (mw *instrumentingMiddleware) GetCAs(ctx context.Context, caType secrets.CAType) (CAs []secrets.Cert, err error) {
	defer func(begin time.Time) {
		lvs := []string{"method", "GetCAs", "error", fmt.Sprint(err != nil)}
		mw.requestCount.With(lvs...).Add(1)
		mw.requestLatency.With(lvs...).Observe(time.Since(begin).Seconds())
	}(time.Now())
	return mw.next.GetCAs(ctx, caType)
}

func (mw *instrumentingMiddleware) CreateCA(ctx context.Context, caType secrets.CAType, caName string, privateKeyMetadata secrets.PrivateKeyMetadata, subject secrets.Subject, caTTL int, enrollerTTL int) (cretedCa secrets.Cert, err error) {
	defer func(begin time.Time) {
		lvs := []string{"method", "CreateCA", "error", fmt.Sprint(err != nil)}
		mw.requestCount.With(lvs...).Add(1)
		mw.requestLatency.With(lvs...).Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mw.next.CreateCA(ctx, caType, caName, privateKeyMetadata, subject, caTTL, enrollerTTL)
}

func (mw *instrumentingMiddleware) ImportCA(ctx context.Context, caType secrets.CAType, caName string, certificate x509.Certificate, privateKey secrets.PrivateKey, enrollerTTL int) (createdCa secrets.Cert, err error) {
	defer func(begin time.Time) {
		lvs := []string{"method", "ImportCA", "error", fmt.Sprint(err != nil)}
		mw.requestCount.With(lvs...).Add(1)
		mw.requestLatency.With(lvs...).Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mw.next.ImportCA(ctx, caType, caName, certificate, privateKey, enrollerTTL)
}

func (mw *instrumentingMiddleware) DeleteCA(ctx context.Context, caType secrets.CAType, CA string) (err error) {
	defer func(begin time.Time) {
		lvs := []string{"method", "DeleteCA", "error", fmt.Sprint(err != nil)}
		mw.requestCount.With(lvs...).Add(1)
		mw.requestLatency.With(lvs...).Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mw.next.DeleteCA(ctx, caType, CA)
}

func (mw *instrumentingMiddleware) GetIssuedCerts(ctx context.Context, caType secrets.CAType, caName string) (certs []secrets.Cert, err error) {
	defer func(begin time.Time) {
		lvs := []string{"method", "GetIssuedCerts", "error", fmt.Sprint(err != nil)}
		mw.requestCount.With(lvs...).Add(1)
		mw.requestLatency.With(lvs...).Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mw.next.GetIssuedCerts(ctx, caType, caName)
}
func (mw *instrumentingMiddleware) GetCert(ctx context.Context, caType secrets.CAType, caName string, serialNumber string) (cert secrets.Cert, err error) {
	defer func(begin time.Time) {
		lvs := []string{"method", "GetCert", "error", fmt.Sprint(err != nil)}
		mw.requestCount.With(lvs...).Add(1)
		mw.requestLatency.With(lvs...).Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mw.next.GetCert(ctx, caType, caName, serialNumber)
}

func (mw *instrumentingMiddleware) DeleteCert(ctx context.Context, caType secrets.CAType, caName string, serialNumber string) (err error) {
	defer func(begin time.Time) {
		lvs := []string{"method", "DeleteCert", "error", fmt.Sprint(err != nil)}
		mw.requestCount.With(lvs...).Add(1)
		mw.requestLatency.With(lvs...).Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mw.next.DeleteCert(ctx, caType, caName, serialNumber)
}

func (mw *instrumentingMiddleware) SignCertificate(ctx context.Context, caType secrets.CAType, caName string, csr x509.CertificateRequest, signVerbatim bool) (crt string, err error) {
	defer func(begin time.Time) {
		lvs := []string{"method", "SignCertificate", "error", fmt.Sprint(err != nil)}
		mw.requestCount.With(lvs...).Add(1)
		mw.requestLatency.With(lvs...).Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mw.next.SignCertificate(ctx, caType, caName, csr, signVerbatim)
}
