package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"github.com/globalsign/pemfile"
	_ "github.com/lamassuiot/lamassu-ca/pkg/docs"
	"github.com/lamassuiot/lamassu-ca/pkg/secrets"
	"net/http"
	"os"
	"os/signal"
	"path"
	"syscall"
	"time"

	"github.com/globalsign/est"
	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	kitprometheus "github.com/go-kit/kit/metrics/prometheus"
	"github.com/go-openapi/runtime/middleware"
	"github.com/lamassuiot/lamassu-ca/pkg/api"
	"github.com/lamassuiot/lamassu-ca/pkg/auth"
	"github.com/lamassuiot/lamassu-ca/pkg/configs"
	"github.com/lamassuiot/lamassu-ca/pkg/discovery/consul"
	"github.com/lamassuiot/lamassu-ca/pkg/secrets/vault"
	stdprometheus "github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	jaegercfg "github.com/uber/jaeger-client-go/config"
)

const (
	defaultListenAddr   = "https://localhost:8087/v1"
	configFilePath = "/home/xpb/Desktop/ikl/lamassu/lamassu-ca/pkg/configs/serverconfig.json"
)

//go:generate swagger generate spec
func main() {

	var logger log.Logger
	{
		logger = log.NewJSONLogger(os.Stdout)
		logger = log.With(logger, "ts", log.DefaultTimestampUTC)
		logger = log.With(logger, "caller", log.DefaultCaller)
		logger = level.NewFilter(logger, level.AllowInfo())
	}

	/*
	EST
	*/

	var ca *secrets.VaultService

	// Load and process configuration.
	estcfg, err := configs.ConfigFromFile(configFilePath)
	if err != nil {
		level.Error(logger).Log("failed to read configuration file: %v", err)
	}

	var serverKey interface{}
	var serverCerts []*x509.Certificate
	var clientCACerts []*x509.Certificate

	serverKey, err = pemfile.ReadPrivateKey(estcfg.TLS.Key)
	if err != nil {
		level.Error(logger).Log("failed to read server private key   file: %v", err)
	}

	serverCerts, err = pemfile.ReadCerts(estcfg.TLS.Certs)
	if err != nil {
		level.Error(logger).Log("failed to read server certificates from file: %v", err)
	}

	for _, certPath := range estcfg.TLS.ClientCAs {
		certs, err := pemfile.ReadCerts(certPath)
		if err != nil {
			level.Error(logger).Log("failed to read caservice CA certificates from file: %v", err)
		}
		clientCACerts = append(clientCACerts, certs...)
	}

	var tlsCerts [][]byte
	for i := range serverCerts {
		tlsCerts = append(tlsCerts, serverCerts[i].Raw)
	}

	clientCAs := x509.NewCertPool()
	for _, cert := range clientCACerts {
		clientCAs.AddCert(cert)
	}

	tlsCfg := &tls.Config{
		MinVersion:       tls.VersionTLS12,
		CurvePreferences: []tls.CurveID{tls.CurveP521, tls.CurveP384, tls.CurveP256},
		ClientAuth:       tls.VerifyClientCertIfGiven,
		Certificates: []tls.Certificate{
			{
				Certificate: tlsCerts,
				PrivateKey:  serverKey,
				Leaf:        serverCerts[0],
			},
		},
		ClientCAs: clientCAs,
	}

	/*********************************************************************/

	cfg, err := configs.NewConfig("ca")
	if err != nil {
		level.Error(logger).Log("err", err, "msg", "Could not read environment configuration values")
		os.Exit(1)
	}
	level.Info(logger).Log("msg", "Environment configuration values loaded")

	auth := auth.NewAuth(cfg.KeycloakHostname, cfg.KeycloakPort, cfg.KeycloakProtocol, cfg.KeycloakRealm, cfg.KeycloakCA)
	level.Info(logger).Log("msg", "Connection established with authentication system")

	secretsVault, err := vault.NewVaultSecrets(cfg.VaultAddress, cfg.VaultRoleID, cfg.VaultSecretID, cfg.VaultCA, logger)
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
	tracer, closer, err := jcfg.NewTracer()
	if err != nil {
		level.Error(logger).Log("err", err, "msg", "Could not start Jaeger tracer")
		os.Exit(1)
	}
	defer closer.Close()
	level.Info(logger).Log("msg", "Jaeger tracer started")

	fieldKeys := []string{"method", "error"}

	var s api.Service
	{
		s = api.NewCAService(secretsVault)
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

	consulsd, err := consul.NewServiceDiscovery(cfg.ConsulProtocol, cfg.ConsulHost, cfg.ConsulPort, cfg.ConsulCA, logger)
	if err != nil {
		level.Error(logger).Log("err", err, "msg", "Could not start connection with Consul Service Discovery")
		os.Exit(1)
	}
	level.Info(logger).Log("msg", "Connection established with Consul Service Discovery")
	err = consulsd.Register("https", "ca", cfg.Port)
	if err != nil {
		level.Error(logger).Log("err", err, "msg", "Could not register service liveness information to Consul")
		os.Exit(1)
	}
	level.Info(logger).Log("msg", "Service liveness information registered to Consul")

	mux := http.NewServeMux()

	mux.Handle("/v1/", api.MakeHTTPHandler(s, log.With(logger, "component", "HTTPS"), auth, tracer))
	http.Handle("/v1/docs", middleware.SwaggerUI(middleware.SwaggerUIOpts{
		BasePath: "/v1/",
		SpecURL:  path.Join("/", "swagger.json"),
		Path:     "docs",
	}, mux))
	http.Handle("/", accessControl(mux, cfg.EnrollerUIProtocol, cfg.EnrollerUIHost, cfg.EnrollerUIPort))
	http.Handle("/metrics", promhttp.Handler())
	http.Handle("/swagger.json", http.FileServer(http.Dir("./docs")))




	/*
	EST server
	*/

	ca = secrets.NewVaultService(secretsVault)

	// Create server mux.TODO: Fill nils
	r, err := est.NewRouter(&est.ServerConfig{
		CA:             ca,
		Logger:         nil,
		AllowedHosts:   estcfg.AllowedHosts,
		Timeout:        time.Duration(estcfg.Timeout) * time.Second,
		RateLimit:      estcfg.RateLimit,
	})
	if err != nil {
		level.Error(logger).Log("failed to create new EST router: %v", err)
	}


	// Create and start server.

	server := &http.Server{
		Addr:  ":8080" ,
		Handler: r,
		TLSConfig: tlsCfg,
	}


	errs := make(chan error)
	go func() {
		c := make(chan os.Signal)
		signal.Notify(c, syscall.SIGINT, syscall.SIGTERM)
		errs <- fmt.Errorf("%s", <-c)
	}()

	go func() {
		level.Info(logger).Log("transport", "HTTPS", "address", ":" + cfg.Port, "msg", "listening")
		errs <- http.ListenAndServeTLS(":"+cfg.Port, cfg.CertFile, cfg.KeyFile, nil)
	}()

	go server.ListenAndServeTLS("", "")

	level.Info(logger).Log("exit", <-errs)
	err = consulsd.Deregister()
	if err != nil {
		level.Error(logger).Log("err", err, "msg", "Could not deregister service liveness information from Consul")
		os.Exit(1)
	}
	level.Info(logger).Log("msg", "Service liveness information deregistered from Consul")
}

func accessControl(h http.Handler, enrollerUIProtocol string, enrollerUIHost string, enrollerUIPort string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		/*var uiURL string
		if enrollerUIPort == "" {
			uiURL = enrollerUIProtocol + "://" + enrollerUIHost
		} else {
			uiURL = enrollerUIProtocol + "://" + enrollerUIHost + ":" + enrollerUIPort
		}*/
		//w.Header().Set("Access-Control-Allow-Origin", "http://127.0.0.1:3000")
		//w.Header().Set("Access-Control-Allow-Origin", uiURL)
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS, PUT, DELETE")
		w.Header().Set("Access-Control-Allow-Headers", "Origin, Content-Type, Authorization")

		if r.Method == "OPTIONS" {
			return
		}

		h.ServeHTTP(w, r)
	})
}
