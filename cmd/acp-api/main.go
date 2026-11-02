// Command acp-api serves an internal, mutually-authenticated Control Plane
// to Runtime RunIntent API. It has no public user-facing endpoints.
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
	dsn      string
	cert     string
	key      string
	ca       string
	identity string
	addr     string
}

func readConfig(getenv func(string) string) (config, error) {
	c := config{
		dsn:      getenv("RUNTIME_DATABASE_URL"),
		cert:     getenv("RUNTIME_TLS_CERT"),
		key:      getenv("RUNTIME_TLS_KEY"),
		ca:       getenv("RUNTIME_CLIENT_CA"),
		identity: getenv("RUNTIME_ACP_SPIFFE_ID"),
		addr:     getenv("RUNTIME_ACP_LISTEN_ADDR"),
	}
	if c.dsn == "" || c.cert == "" || c.key == "" || c.ca == "" || c.identity == "" {
		return config{}, errors.New("required mTLS and Runtime database configuration missing")
	}
	if c.addr == "" {
		c.addr = "127.0.0.1:8443"
	}
	return c, nil
}

func loadTLS(certFile, keyFile, caFile string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("load server TLS key pair: %w", err)
	}
	pem, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("read trusted ACP client CA: %w", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pem) {
		return nil, errors.New("trusted ACP CA PEM is invalid")
	}
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    roots,
		Certificates: []tls.Certificate{cert},
	}, nil
}

func runServer(ctx context.Context, c config) error {
	tlsConf, err := loadTLS(c.cert, c.key, c.ca)
	if err != nil {
		return err
	}
	pool, err := pgxpool.New(ctx, c.dsn)
	if err != nil {
		return fmt.Errorf("create Runtime PostgreSQL pool: %w", err)
	}
	defer pool.Close()
	if err = pool.Ping(ctx); err != nil {
		return errors.New("Runtime PostgreSQL unavailable")
	}
	store := postgres.New(pool)
	if err = store.Migrate(ctx); err != nil {
		return fmt.Errorf("migrate Runtime schema: %w", err)
	}
	handler, err := acphttp.NewHandler(store, c.identity)
	if err != nil {
		return err
	}

	srv := &http.Server{
		Addr:              c.addr,
		Handler:           handler,
		TLSConfig:         tlsConf,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    16 * 1024,
	}
	errs := make(chan error, 1)
	go func() { errs <- srv.ListenAndServeTLS("", "") }()
	select {
	case err := <-errs:
		return err
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			return err
		}
		<-errs
		return nil
	}
}

func main() {
	c, err := readConfig(os.Getenv)
	if err != nil {
		log.Fatal(err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
	defer stop()
	if err := runServer(ctx, c); err != nil {
		log.Fatal(err)
	}
}
