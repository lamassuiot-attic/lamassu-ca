package main

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"path"
	"strings"
	"syscall"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	kitprometheus "github.com/go-kit/kit/metrics/prometheus"
	"github.com/go-openapi/runtime/middleware"
	"github.com/lamassuiot/lamassu-ca/pkg/api"
	"github.com/lamassuiot/lamassu-ca/pkg/configs"
	"github.com/lamassuiot/lamassu-ca/pkg/secrets/vault"
	"github.com/lamassuiot/lamassu-ca/pkg/utils"
	"github.com/opentracing/opentracing-go"
	stdprometheus "github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	jaegercfg "github.com/uber/jaeger-client-go/config"
	jaegerlog "github.com/uber/jaeger-client-go/log"
)

func main() {

	var logger log.Logger
	logger = log.NewJSONLogger(os.Stdout)
	logger = level.NewFilter(logger, level.AllowDebug())
	logger = log.With(logger, "ts", log.DefaultTimestampUTC)
	logger = log.With(logger, "caller", log.DefaultCaller)

	/*********************************************************************/

	cfg, err := configs.NewConfig("")
	if err != nil {
		level.Error(logger).Log("err", err, "msg", "Could not read environment configuration values")
		os.Exit(1)
	}
	level.Info(logger).Log("msg", "Environment configuration values loaded")

	secretsVault, err := vault.NewVaultSecrets(cfg.VaultAddress, cfg.VaultPkiCaPath, cfg.VaultRoleID, cfg.VaultSecretID, cfg.VaultCA, cfg.VaultUnsealKeysFile, cfg.OcspUrl, logger)
	if err != nil {
		level.Error(logger).Log("err", err, "msg", "Could not start connection with Vault Secret Engine")
		os.Exit(1)
	}
	level.Info(logger).Log("msg", "Connection established with secret engine")

	jcfg, err := jaegercfg.FromEnv()
	if err != nil {
		level.Error(logger).Log("err", err, "msg", "Could not load Jaeger configuration values fron environment")
		os.Exit(1)
	}
	level.Info(logger).Log("msg", "Jaeger configuration values loaded")

	tracer, closer, err := jcfg.NewTracer(
		jaegercfg.Logger(jaegerlog.StdLogger),
	)
	opentracing.SetGlobalTracer(tracer)

	if err != nil {
		level.Error(logger).Log("err", err, "msg", "Could not start Jaeger tracer")
		os.Exit(1)
	}
	defer closer.Close()
	level.Info(logger).Log("msg", "Jaeger tracer started")

	fieldKeys := []string{"method", "error"}

	// amqpConn, err := amqp.Dial("amqp://guest:guest@" + cfg.AmqpIP + ":" + cfg.AmqpPort + "")
	// if err != nil {
	// 	level.Error(logger).Log("err", err, "msg", "Failed to connect to AMQP")
	// 	os.Exit(1)
	// }

	var s api.Service
	{
		s = api.NewCAService(logger, secretsVault)
		s = api.LoggingMiddleware(logger)(s)
		s = api.NewInstrumentingMiddleware(
			kitprometheus.NewCounterFrom(stdprometheus.CounterOpts{
				Namespace: "enroller",
				Subsystem: "enroller_service",
				Name:      "request_count",
				Help:      "Number of requests received.",
			}, fieldKeys),
			kitprometheus.NewSummaryFrom(stdprometheus.SummaryOpts{
				Namespace: "enroller",
				Subsystem: "enroller_service",
				Name:      "request_latency_microseconds",
				Help:      "Total duration of requests in microseconds.",
			}, fieldKeys),
		)(s)
	}

	mux := http.NewServeMux()

	mux.Handle("/v1/", api.MakeHTTPHandler(s, log.With(logger, "component", "HTTPS"), tracer))
	http.Handle("/v1/docs", middleware.SwaggerUI(middleware.SwaggerUIOpts{
		BasePath: "/v1/",
		SpecURL:  path.Join("/", "swagger.json"),
		Path:     "docs",
	}, mux))
	http.Handle("/", accessControl(mux))
	http.Handle("/metrics", promhttp.Handler())
	http.Handle("/swagger.json", http.FileServer(http.Dir("./docs")))

	errs := make(chan error)
	go func() {
		c := make(chan os.Signal)
		signal.Notify(c, syscall.SIGINT, syscall.SIGTERM)
		errs <- fmt.Errorf("%s", <-c)
	}()

	go func() {
		if strings.ToLower(cfg.Protocol) == "https" {
			if cfg.MutualTLSEnabled {
				mTlsCertPool, err := utils.CreateCAPool(cfg.MutualTLSClientCA)
				if err != nil {
					level.Error(logger).Log("err", err, "msg", "Could not create mTls Cert Pool")
					os.Exit(1)
				}
				tlsConfig := &tls.Config{
					ClientCAs:  mTlsCertPool,
					ClientAuth: tls.RequireAndVerifyClientCert,
				}
				tlsConfig.BuildNameToCertificate()

				http := &http.Server{
					Addr:      ":" + cfg.Port,
					TLSConfig: tlsConfig,
				}

				level.Info(logger).Log("transport", "Mutual TLS", "address", ":"+cfg.Port, "msg", "listening")
				errs <- http.ListenAndServeTLS(cfg.CertFile, cfg.KeyFile)

			} else {
				level.Info(logger).Log("transport", "HTTPS", "address", ":"+cfg.Port, "msg", "listening")
				errs <- http.ListenAndServeTLS(":"+cfg.Port, cfg.CertFile, cfg.KeyFile, nil)
			}
		} else if strings.ToLower(cfg.Protocol) == "http" {
			level.Info(logger).Log("transport", "HTTP", "address", ":"+cfg.Port, "msg", "listening")
			errs <- http.ListenAndServe(":"+cfg.Port, nil)
		} else {
			level.Error(logger).Log("err", "msg", "Unknown protocol")
			os.Exit(1)
		}
	}()

	level.Info(logger).Log("exit", <-errs)
}

func accessControl(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS, PUT, DELETE")
		w.Header().Set("Access-Control-Allow-Headers", "Origin, Content-Type, Authorization")

		if r.Method == "OPTIONS" {
			return
		}

		h.ServeHTTP(w, r)
	})
}
