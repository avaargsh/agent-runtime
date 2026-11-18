// Command decision-authority-api serves the Runtime-owned committed invocation
// observation over a dedicated, tenant-pinned mutual TLS listener. No DDL,
// Run creation, workflow start, or Decision authorization is performed here.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
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

func serve(ctx context.Context) error {
	get := os.Getenv
	dsn, cert, key, ca := get("RUNTIME_DECISION_DATABASE_URL"), get("RUNTIME_DECISION_TLS_CERT"),
		get("RUNTIME_DECISION_TLS_KEY"), get("RUNTIME_DECISION_CLIENT_CA")
	peer, tenant := get("RUNTIME_DECISION_PEER_SPIFFE_ID"), get("RUNTIME_DECISION_TENANT")
	addr := get("RUNTIME_DECISION_LISTEN_ADDR")
	if addr == "" {
		addr = "127.0.0.1:8445"
	}
	if dsn == "" || cert == "" || key == "" || ca == "" || peer == "" || tenant == "" {
		return errors.New("missing Runtime Decision authority configuration")
	}
	pair, err := tls.LoadX509KeyPair(cert, key)
	if err != nil {
		return errors.New("invalid Runtime Decision TLS key pair")
	}
	pem, err := os.ReadFile(ca)
	if err != nil {
		return errors.New("Runtime Decision client CA unavailable")
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pem) {
		return errors.New("invalid Runtime Decision client CA")
	}
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return errors.New("invalid Runtime Decision database configuration")
	}
	cfg.ConnConfig.RuntimeParams["default_transaction_read_only"] = "on"
	cfg.MaxConns = 8
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return errors.New("Runtime Decision database unavailable")
	}
	defer pool.Close()
	pingCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	err = pool.Ping(pingCtx)
	cancel()
	if err != nil {
		return errors.New("Runtime Decision database unavailable")
	}
	handler, err := acphttp.NewDecisionAuthorityHandler(postgres.New(pool), peer, tenant)
	if err != nil {
		return err
	}
	srv := &http.Server{
		Addr: addr, Handler: handler,
		TLSConfig: &tls.Config{MinVersion: tls.VersionTLS13, ClientAuth: tls.RequireAndVerifyClientCert,
			ClientCAs: roots, Certificates: []tls.Certificate{pair}},
		ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 5 * time.Second,
		WriteTimeout: 5 * time.Second, IdleTimeout: 15 * time.Second, MaxHeaderBytes: 8192,
	}
	errs := make(chan error, 1)
	go func() { errs <- srv.ListenAndServeTLS("", "") }()
	select {
	case err := <-errs:
		return err
	case <-ctx.Done():
		stopCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := srv.Shutdown(stopCtx); err != nil {
			_ = srv.Close()
			return err
		}
		<-errs
		return nil
	}
}

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
	defer cancel()
	if err := serve(ctx); err != nil {
		log.Fatal("Runtime Decision authority service stopped")
	}
}
