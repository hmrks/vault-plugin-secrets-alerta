package alertasecrets

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/require"
)

const (
	envVarRunAccTests       = "VAULT_ACC"
	envVarAlertaApiURL      = "TEST_ALERTA_API_URL"
	envVarAlertaAuthKey     = "TEST_ALERTA_AUTH_KEY"
	envVarAlertaUser        = "TEST_ALERTA_USER"
	envVarAlertaScopes      = "TEST_ALERTA_SCOPES"
	envVarAlertaDescription = "TEST_ALERTA_DESCRIPTION"
)

// runAcceptanceTests will separate unit tests from
// acceptance tests, which will make active requests
// to the target API.
var runAcceptanceTests = os.Getenv(envVarRunAccTests) == "1"

func getTestBackend(tb testing.TB) (*alertaBackend, logical.Storage) {
	tb.Helper()

	config := logical.TestBackendConfig()
	config.StorageView = new(logical.InmemStorage)
	config.Logger = hclog.NewNullLogger()
	config.System = logical.TestSystemView()

	b, err := Factory(context.Background(), config)
	if err != nil {
		tb.Fatal(err)
	}

	return b.(*alertaBackend), config.StorageView
}

// testEnv creates an object to store and track testing environment
// resources
type testEnv struct {
	AuthKey string
	ApiURL  string

	User        string
	Scopes      string
	Description string

	Backend logical.Backend
	Context context.Context
	Storage logical.Storage

	// SecretKeyID tracks the API key, for checking rotations
	SecretKeyID string

	// KeyIDs tracks the generated keys, to make sure we clean up
	KeyIDs []string
}

// AddConfig adds the configuration to the test backend.
func (e *testEnv) AddConfig(t *testing.T) {
	req := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "config",
		Storage:   e.Storage,
		Data: map[string]interface{}{
			"auth_key": e.AuthKey,
			"api_url":  e.ApiURL,
		},
	}
	resp, err := e.Backend.HandleRequest(e.Context, req)
	require.Nil(t, resp)
	require.Nil(t, err)
}

// AddAlertaRole adds a role for the Alerta API key.
func (e *testEnv) AddAlertaRole(t *testing.T) {
	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "role/test-alerta-role",
		Storage:   e.Storage,
		Data: map[string]interface{}{
			"user":        e.User,
			"scopes":      strings.Split(e.Scopes, ","),
			"description": e.Description,
		},
	}
	resp, err := e.Backend.HandleRequest(e.Context, req)
	require.Nil(t, resp)
	require.Nil(t, err)
}

// ReadAlertaKey retrieves the API key
// based on a Vault role.
func (e *testEnv) ReadAlertaKey(t *testing.T) {
	req := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "keys/test-alerta-role",
		Storage:   e.Storage,
	}
	resp, err := e.Backend.HandleRequest(e.Context, req)
	require.Nil(t, err)
	require.NotNil(t, resp)

	if t, ok := resp.Data["alerta_api_key_id"]; ok {
		e.KeyIDs = append(e.KeyIDs, t.(string))
	}
	require.NotEmpty(t, resp.Data["alerta_api_key_id"])

	if e.SecretKeyID != "" {
		require.NotEqual(t, e.SecretKeyID, resp.Data["alerta_api_key_id"])
	}

	// collect secret IDs to revoke at end of test
	require.NotNil(t, resp.Secret)
	if t, ok := resp.Secret.InternalData["alerta_api_key_id"]; ok {
		e.SecretKeyID = t.(string)
	}
}

// CleanupAlertaKeys removes the API keys created
// when the test completes.
func (e *testEnv) CleanupAlertaKeys(t *testing.T) {
	if len(e.KeyIDs) == 0 {
		t.Fatalf("expected 2 key ids, got: %d", len(e.KeyIDs))
	}

	for _, key_id := range e.KeyIDs {
		b := e.Backend.(*alertaBackend)
		client, err := b.getClient(e.Context, e.Storage)
		if err != nil {
			t.Fatal("fatal getting client")
		}
		if _, err := client.deleteKey(e.Context, key_id); err != nil {
			t.Fatalf("unexpected error deleting api key: %s", err)
		}
	}
}
