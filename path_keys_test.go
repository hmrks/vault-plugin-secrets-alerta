package alertasecrets

import (
	"context"
	"os"
	"testing"
	"time"

	log "github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/sdk/helper/logging"
	"github.com/hashicorp/vault/sdk/logical"
)

// newAcceptanceTestEnv creates a test environment for credentials
func newAcceptanceTestEnv() (*testEnv, error) {
	ctx := context.Background()

	maxLease, _ := time.ParseDuration("60s")
	defaultLease, _ := time.ParseDuration("30s")
	conf := &logical.BackendConfig{
		System: &logical.StaticSystemView{
			DefaultLeaseTTLVal: defaultLease,
			MaxLeaseTTLVal:     maxLease,
		},
		Logger: logging.NewVaultLogger(log.Debug),
	}
	b, err := Factory(ctx, conf)
	if err != nil {
		return nil, err
	}
	return &testEnv{
		AuthKey:     os.Getenv(envVarAlertaAuthKey),
		ApiURL:      os.Getenv(envVarAlertaApiURL),
		User:        os.Getenv(envVarAlertaUser),
		Scopes:      os.Getenv(envVarAlertaScopes),
		Description: os.Getenv(envVarAlertaDescription),
		Backend:     b,
		Context:     ctx,
		Storage:     &logical.InmemStorage{},
	}, nil
}

// TestAcceptanceAlertaKey tests a series of steps to make
// sure the role and key creation work correctly.
func TestAcceptanceAlertaKey(t *testing.T) {
	if !runAcceptanceTests {
		t.SkipNow()
	}

	acceptanceTestEnv, err := newAcceptanceTestEnv()
	if err != nil {
		t.Fatal(err)
	}

	t.Run("add config", acceptanceTestEnv.AddConfig)
	t.Run("add alerta role", acceptanceTestEnv.AddAlertaRole)
	t.Run("read alerta api key", acceptanceTestEnv.ReadAlertaKey)
	t.Run("read alerta api key", acceptanceTestEnv.ReadAlertaKey)
	t.Run("cleanup api keys", acceptanceTestEnv.CleanupAlertaKeys)
}
