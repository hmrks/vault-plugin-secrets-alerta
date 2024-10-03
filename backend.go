package alertasecrets

import (
	"context"
	"strings"
	"sync"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

// Factory returns a new backend as logical.Backend
func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b := backend()
	if err := b.Setup(ctx, conf); err != nil {
		return nil, err
	}
	return b, nil
}

// alertaBackend defines an object that
// extends the Vault backend and stores the
// target API's client.
type alertaBackend struct {
	*framework.Backend
	lock sync.RWMutex
	// write a client for alerta
	client *alertaClient
}

// backend defines the target API backend
// for Vault. It must include each path
// and the secrets it will store.
func backend() *alertaBackend {
	var b = alertaBackend{}

	b.Backend = &framework.Backend{
		Help: strings.TrimSpace(backendHelp),
		PathsSpecial: &logical.Paths{
			SealWrapStorage: []string{
				"config",
				"role/*",
			},
		},
		Paths: framework.PathAppend(
			pathRole(&b),
			[]*framework.Path{
				pathConfig(&b),
				pathKeys(&b),
			},
		),
		Secrets: []*framework.Secret{
			b.alertaToken(),
		},
		BackendType: logical.TypeLogical,
		Invalidate:  b.invalidate,
	}
	return &b
}

func (b *alertaBackend) reset() {
	b.lock.Lock()
	defer b.lock.Unlock()
	b.client = nil
}

func (b *alertaBackend) invalidate(ctx context.Context, key string) {
	if key == "config" {
		b.reset()
	}
}

// getClient locks the backend as it configures and creates a
// a new client for the target API
func (b *alertaBackend) getClient(ctx context.Context, s logical.Storage) (*alertaClient, error) {
	b.lock.RLock()
	unlockFunc := b.lock.RUnlock
	defer func() { unlockFunc() }()

	if b.client != nil {
		return b.client, nil
	}

	b.lock.RUnlock()
	b.lock.Lock()
	unlockFunc = b.lock.Unlock

	config, err := getConfig(ctx, s)
	if err != nil {
		return nil, err
	}

	if b.client == nil {
		if config == nil {
			config = new(alertaConfig)
		}
	}

	b.client, err = newClient(config)
	if err != nil {
		return nil, err
	}

	return b.client, nil
}

// backendHelp should contain help information for the backend
const backendHelp = `
The Alerta secrets backend dynamically generates application tokens
that can be used to send alerts to the Alerta API.
`

func (b *alertaBackend) pathRoleExistenceCheck(ctx context.Context, req *logical.Request, d *framework.FieldData) (bool, error) {
	name := d.Get("name").(string)

	// Check if the role exists in the backend storage
	entry, err := req.Storage.Get(ctx, "role/"+name)
	if err != nil {
		return false, err
	}

	// If no entry is found, return false, meaning the role doesn't exist
	if entry == nil {
		return false, nil
	}

	// If the entry exists, return true
	return true, nil
}
