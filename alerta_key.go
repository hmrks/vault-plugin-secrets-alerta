package alertasecrets

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const (
	alertaKeyType = "alerta_api_key"
)

// alertaKey defines a secret for the Alerta API Key
type alertaKey struct {
	ID         string    `json:"alerta_api_key_id"`
	Key        string    `json:"alerta_api_key"`
	ExpireTime time.Time `json:"expire_time"`
	RoleName   string    `json:"role_name"`
}

// alertaKey defines a secret to store for a given role
// and how it should be revoked or renewed.
func (b *alertaBackend) alertaKey() *framework.Secret {
	return &framework.Secret{
		Type: alertaKeyType,
		Fields: map[string]*framework.FieldSchema{
			"alerta_api_key": {
				Type:        framework.TypeString,
				Description: "Alerta API key",
			},
			"alerta_api_key_id": {
				Type:        framework.TypeString,
				Description: "Alerta API key ID",
			},
			"expire_time": {
				Type:        framework.TypeString,
				Description: "Time the API key expires",
			},
		},
		Revoke: b.keyRevoke,
		Renew:  b.keyRenew,
	}
}

// keyRevoke removes the key from the Vault storage API and calls the client to revoke the key
func (b *alertaBackend) keyRevoke(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	client, err := b.getClient(ctx, req.Storage)
	if err != nil {
		return nil, fmt.Errorf("error getting client: %w", err)
	}

	apiKeyId := ""
	apiKeyIdRaw, ok := req.Secret.InternalData["alerta_api_key_id"]
	if ok {
		apiKeyId, ok = apiKeyIdRaw.(string)
		if !ok {
			return nil, fmt.Errorf("invalid value for Alerta API key ID in secret internal data")
		}
	}

	if err := b.deleteKey(ctx, client, apiKeyId); err != nil {
		return nil, fmt.Errorf("error revoking Alerta API Key: %w", err)
	}
	return nil, nil
}

// keyRenew calls the client to create a new key and stores it in the Vault storage API
func (b *alertaBackend) keyRenew(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	roleRaw, ok := req.Secret.InternalData["role_name"]
	if !ok {
		return nil, fmt.Errorf("secret is missing role_name internal data")
	}

	role := roleRaw.(string)
	roleEntry, err := b.getRole(ctx, req.Storage, role)
	if err != nil {
		return nil, fmt.Errorf("error retrieving role: %w", err)
	}

	if roleEntry == nil {
		return nil, errors.New("error retrieving role: role is nil")
	}

	resp := &logical.Response{Secret: req.Secret}

	if roleEntry.TTL > 0 {
		resp.Secret.TTL = roleEntry.TTL
	}
	if roleEntry.MaxTTL > 0 {
		resp.Secret.MaxTTL = roleEntry.MaxTTL
	}

	return resp, nil
}

func (b *alertaBackend) deleteKey(ctx context.Context, c *alertaClient, id string) error {
	_, err := c.deleteKey(ctx, id)
	if err != nil {
		return fmt.Errorf("error deleting Alerta API key: %w", err)
	}

	return nil
}

func (b *alertaBackend) createKey(ctx context.Context, c *alertaClient, r *alertaRoleEntry) (*alertaKey, error) {

	response, err := c.createKey(ctx, r.User, r.Scopes, fmt.Sprintf("%s at %s", r.Description, time.Now().Format(time.RFC3339)), time.Now().Add(r.MaxTTL).UTC().Format("2006-01-02T15:04:05.000Z"))

	if err != nil {
		return nil, fmt.Errorf("error creating Alerta API Key: %w", err)
	}

	layout := time.RFC3339

	expireTime, err := time.Parse(layout, response.ExpireTime)
	if err != nil {
		return nil, fmt.Errorf("error parsing expire time: %w", err)
	}

	return &alertaKey{
		ID:         response.ID,
		Key:        response.Key,
		ExpireTime: expireTime,
		RoleName:   r.Name,
	}, nil
}
