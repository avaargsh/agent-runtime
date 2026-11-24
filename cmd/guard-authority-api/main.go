// Command guard-authority-api serves the Runtime-owned current
// Run/Attempt/Turn observation to one explicitly pinned Guard workload.
// The database connection is read-only and this process performs no schema
// migrations or Run mutations.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/avaargsh/agent-runtime/internal/acphttp"
	"github.com/avaargsh/agent-runtime/internal/store/postgres"
	"github.com/jackc/pgx/v5/pgxpool"
)

type config struct {
	dsn, cert, key, ca, peer, tenant, addr string
}

func readConfig(getenv func(string) string) (config, error) {
	c := config{
		dsn:    getenv("RUNTIME_GUARD_AUTHORITY_DATABASE_URL"),
		cert:   getenv("RUNTIME_GUARD_AUTHORITY_TLS_CERT"),
		key:    getenv("RUNTIME_GUARD_AUTHORITY_TLS_KEY"),
		ca:     getenv("RUNTIME_GUARD_AUTHORITY_CLIENT_CA"),
		peer:   getenv("RUNTIME_GUARD_AUTHORITY_PEER_SPIFFE_ID"),
		tenant: getenv("RUNTIME_GUARD_AUTHORITY_TENANT"),
		addr:   getenv("RUNTIME_GUARD_AUTHORITY_LISTEN_ADDR"),
	}
	if c.dsn == "" || c.cert == "" || c.key == "" || c.ca == "" || c.peer == "" || c.tenant == "" {
		return config{}, errors.New("missing Guard authority API configuration")
	}
	if c.addr == "" {
		c.addr = ":8446"
	}
	return c, nil
}

func readOnlyPoolConfig(dsn string) (*pgxpool.Config, error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, errors.New("invalid Guard authority database configuration")
	}
	if cfg.ConnConfig.RuntimeParams == nil {
		cfg.ConnConfig.RuntimeParams = make(map[string]string)
	}
	cfg.ConnConfig.RuntimeParams["default_transaction_read_only"] = "on"
	cfg.MaxConns = 8
	return cfg, nil
}

func loadTLS(certFile, keyFile, caFile string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("load Guard authority server TLS key pair: %w", err)
	}
	pem, err := os.ReadFile(caFile)
	if err != nil {
		return nil, errors.New("Guard authority client CA unavailable")
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pem) {
		return nil, errors.New("invalid Guard authority client CA")
	}
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    roots,
		Certificates: []tls.Certificate{cert},
	}, nil
}

func serve(ctx context.Context, c config) error {
	tlsConfig, err := loadTLS(c.cert, c.key, c.ca)
	if err != nil {
		return err
	}
	poolConfig, err := readOnlyPoolConfig(c.dsn)
	if err != nil {
		return err
	}
	pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
	if err != nil {
		return errors.New("Guard authority database unavailable")
	}
	defer pool.Close()
	pingCtx, cancelPing := context.WithTimeout(ctx, 5*time.Second)
	err = pool.Ping(pingCtx)
	cancelPing()
	if err != nil {
		return errors.New("Guard authority database unavailable")
	}
	handler, err := acphttp.NewGuardExecutionAuthorityHandler(postgres.New(pool), c.peer, c.tenant)
	if err != nil {
		return err
	}
	server := &http.Server{
		Addr:              c.addr,
		Handler:           handler,
		TLSConfig:         tlsConfig,
		ReadHeaderTimeout: 3 * time.Second,
		ReadTimeout:       5 * time.Second,
		WriteTimeout:      5 * time.Second,
		IdleTimeout:       15 * time.Second,
		MaxHeaderBytes:    8192,
	}
	errs := make(chan error, 1)
	go func() { errs <- server.ListenAndServeTLS("", "") }()
	select {
	case err := <-errs:
		return err
	case <-ctx.Done():
		stopCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := server.Shutdown(stopCtx); err != nil {
			_ = server.Close()
			return err
		}
		<-errs
		return nil
	}
}

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
	defer cancel()
	c, err := readConfig(os.Getenv)
	if err != nil {
		log.Fatal(err)
	}
	if err := serve(ctx, c); err != nil {
		log.Fatalf("Runtime Guard authority service stopped: %v", err)
	}
}
