package alertasecrets

import (
	"context"
	"errors"
	"fmt"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

// pathKeys extends the Vault API with a `/creds`
// endpoint for a role. You can choose whether
// or not certain attributes should be displayed,
// required, and named.
func pathKeys(b *alertaBackend) *framework.Path {
	return &framework.Path{
		Pattern: "keys/" + framework.GenericNameRegex("name"),
		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeLowerCaseString,
				Description: "Name of the role",
				Required:    true,
			},
		},
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.ReadOperation:   b.pathKeysRead,
			logical.UpdateOperation: b.pathKeysRead,
		},
		HelpSynopsis:    pathKeysHelpSyn,
		HelpDescription: pathKeysHelpDesc,
	}
}

// pathKeysRead creates a new Alerta token each time it is called if a
// role exists.
func (b *alertaBackend) pathKeysRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	roleName := d.Get("name").(string)

	roleEntry, err := b.getRole(ctx, req.Storage, roleName)
	if err != nil {
		return nil, fmt.Errorf("error retrieving role: %w", err)
	}

	if roleEntry == nil {
		return nil, errors.New("error retrieving role: role is nil")
	}

	roleEntry.Name = roleName

	return b.createUserCreds(ctx, req, roleEntry)
}

// createUserCreds creates a new Alerta token to store into the Vault backend, generates
// a response with the secrets information, and checks the TTL and MaxTTL attributes.
func (b *alertaBackend) createUserCreds(ctx context.Context, req *logical.Request, role *alertaRoleEntry) (*logical.Response, error) {
	client, err := b.getClient(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	token, err := b.createToken(ctx, client, role)
	if err != nil {
		return nil, err
	}

	// The response is divided into two objects (1) internal data and (2) data.
	// If you want to reference any information in your code, you need to
	// store it in internal data!
	resp := b.Secret(alertaTokenType).Response(map[string]interface{}{
		"alerta_api_key":    token.Key,
		"alerta_api_key_id": token.ID,
		"expire_time":       token.ExpireTime,
		"role_name":         role.Name,
	}, map[string]interface{}{
		"alerta_api_key":    token.Key,
		"alerta_api_key_id": token.ID,
		"role_name":         role.Name,
	})

	if role.TTL > 0 {
		resp.Secret.TTL = role.TTL
	}

	if role.MaxTTL > 0 {
		resp.Secret.MaxTTL = role.MaxTTL
	}

	return resp, nil
}

const pathKeysHelpSyn = `
Generate a Alerta API token from a specific Vault role.
`

const pathKeysHelpDesc = `
This path generates an Alerta API user token
based on a particular role.
`
