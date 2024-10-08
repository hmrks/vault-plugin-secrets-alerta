package alertasecrets

import (
	"context"
	"errors"
	"fmt"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const (
	configStoragePath = "config"
)

// alertaConfig includes the minimum configuration
// required to instantiate a new Alerta client.
type alertaConfig struct {
	ApiURL  string `json:"api_url"`
	AuthKey string `json:"auth_key"`
}

func getConfig(ctx context.Context, s logical.Storage) (*alertaConfig, error) {
	entry, err := s.Get(ctx, configStoragePath)
	if err != nil {
		return nil, err
	}

	if entry == nil {
		return nil, nil
	}

	config := new(alertaConfig)
	if err := entry.DecodeJSON(&config); err != nil {
		return nil, fmt.Errorf("error reading root configuration: %w", err)
	}

	// return the config, we are done
	return config, nil
}

// pathConfig extends the Vault API with a `/config`
// endpoint for the backend. You can choose whether
// or not certain attributes should be displayed,
// required, and named. For example, password
// is marked as sensitive and will not be output
// when you read the configuration.
func pathConfig(b *alertaBackend) *framework.Path {
	return &framework.Path{
		Pattern: "config",
		Fields: map[string]*framework.FieldSchema{
			"auth_key": {
				Type:        framework.TypeString,
				Description: "The authentication key for the Alerta API",
				Required:    true,
				DisplayAttrs: &framework.DisplayAttributes{
					Name:      "Auth Key",
					Sensitive: true,
				},
			},
			"api_url": {
				Type:        framework.TypeString,
				Description: "The Api URL for Alerta",
				Required:    true,
				DisplayAttrs: &framework.DisplayAttributes{
					Name:      "Api URL",
					Sensitive: false,
				},
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.pathConfigRead,
			},
			logical.CreateOperation: &framework.PathOperation{
				Callback: b.pathConfigWrite,
			},
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathConfigWrite,
			},
			logical.DeleteOperation: &framework.PathOperation{
				Callback: b.pathConfigDelete,
			},
		},
		ExistenceCheck:  b.pathConfigExistenceCheck,
		HelpSynopsis:    pathConfigHelpSynopsis,
		HelpDescription: pathConfigHelpDescription,
	}
}

// pathConfigExistenceCheck verifies if the configuration exists.
func (b *alertaBackend) pathConfigExistenceCheck(ctx context.Context, req *logical.Request, data *framework.FieldData) (bool, error) {
	out, err := req.Storage.Get(ctx, req.Path)
	if err != nil {
		return false, fmt.Errorf("existence check failed: %w", err)
	}

	return out != nil, nil
}

// pathConfigRead reads the configuration and outputs non-sensitive information.
func (b *alertaBackend) pathConfigRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	config, err := getConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"api_url": config.ApiURL,
		},
	}, nil
}

// pathConfigWrite updates the configuration for the backend
func (b *alertaBackend) pathConfigWrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	config, err := getConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	createOperation := (req.Operation == logical.CreateOperation)

	if config == nil {
		if req.Operation == logical.UpdateOperation {
			return nil, errors.New("config not found during update operation")
		}
		config = new(alertaConfig)
	}

	if api_url, ok := data.GetOk("api_url"); ok {
		config.ApiURL = api_url.(string)
	} else if !ok && createOperation {
		return nil, errors.New("api_url is required")
	}

	if auth_key, ok := data.GetOk("auth_key"); ok {
		config.AuthKey = auth_key.(string)
	} else if !ok && createOperation {
		return nil, errors.New("auth_key is required")
	}

	entry, err := logical.StorageEntryJSON(configStoragePath, config)
	if err != nil {
		return nil, err
	}

	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}

	// reset the client so the next invocation will pick up the new configuration
	b.reset()

	return nil, nil
}

// pathConfigDelete removes the configuration for the backend
func (b *alertaBackend) pathConfigDelete(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	err := req.Storage.Delete(ctx, configStoragePath)

	if err == nil {
		b.reset()
	}

	return nil, err
}

// pathConfigHelpSynopsis summarizes the help text for the configuration
const pathConfigHelpSynopsis = `Configure the Alerta backend`

// pathConfigHelpDescription describes the help text for the configuration
const pathConfigHelpDescription = `
The Alerta secret backend requires credentials for managing
API keys issued to applications working with Alerta.

You must provide the URL for the Alerta API and an
authentication key to authorize requests.
`
