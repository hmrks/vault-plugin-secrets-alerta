package alertasecrets

import (
	"context"
	"fmt"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

// alertaRoleEntry defines the data required
// for a Vault role to access and call the Alerta
// token endpoints
type alertaRoleEntry struct {
	User        string        `json:"user"`
	Scopes      []string      `json:"scopes"`
	Description string        `json:"description"`
	TTL         time.Duration `json:"ttl"`
	MaxTTL      time.Duration `json:"max_ttl"`
	Name        string        `json:"name"`
}

// toResponseData returns response data for a role
func (r *alertaRoleEntry) toResponseData() map[string]interface{} {
	respData := map[string]interface{}{
		"ttl":         r.TTL.Seconds(),
		"max_ttl":     r.MaxTTL.Seconds(),
		"user":        r.User,
		"scopes":      r.Scopes,
		"description": r.Description,
	}
	return respData
}

// pathRole extends the Vault API with a `/role`
// endpoint for the backend. You can choose whether
// or not certain attributes should be displayed,
// required, and named. You can also define different
// path patterns to list all roles.
func pathRole(b *alertaBackend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "role/" + framework.GenericNameRegex("name"),
			Fields: map[string]*framework.FieldSchema{
				"name": {
					Type:        framework.TypeLowerCaseString,
					Description: "Name of the role",
					Required:    true,
				},
				"ttl": {
					Type:        framework.TypeDurationSecond,
					Description: "Default lease for generated credentials. If not set or set to 0, will use system default.",
				},
				"max_ttl": {
					Type:        framework.TypeDurationSecond,
					Description: "Maximum time for role. If not set or set to 0, will use system default.",
					Default:     "90d",
				},
				"user": {
					Type:        framework.TypeString,
					Description: "User to associate with the role",
					Required:    true,
				},
				"scopes": {
					Type:        framework.TypeCommaStringSlice,
					Description: "Scopes for the role",
					Required:    true,
				},
				"description": {
					Type:        framework.TypeString,
					Description: "Description of the role",
					Default:     "Created by Vault",
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.pathRolesRead,
				},
				logical.CreateOperation: &framework.PathOperation{
					Callback: b.pathRolesWrite,
				},
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.pathRolesWrite,
				},
				logical.DeleteOperation: &framework.PathOperation{
					Callback: b.pathRolesDelete,
				},
			},
			ExistenceCheck:  b.pathRoleExistenceCheck,
			HelpSynopsis:    pathRoleHelpSynopsis,
			HelpDescription: pathRoleHelpDescription,
		},
		{
			Pattern: "role/?$",
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ListOperation: &framework.PathOperation{
					Callback: b.pathRolesList,
				},
			},
			ExistenceCheck:  b.pathRoleExistenceCheck,
			HelpSynopsis:    pathRoleListHelpSynopsis,
			HelpDescription: pathRoleListHelpDescription,
		},
	}
}

const (
	pathRoleHelpSynopsis    = `Manages the Vault role for generating Alerta tokens.`
	pathRoleHelpDescription = `
This path allows you to read and write roles used to generate Alerta tokens.
You can configure a role to manage a user's token by setting the username field.
`

	pathRoleListHelpSynopsis    = `List the existing roles in Alerta backend`
	pathRoleListHelpDescription = `Roles will be listed by the role name.`
)

func (b *alertaBackend) getRole(ctx context.Context, s logical.Storage, name string) (*alertaRoleEntry, error) {
	if name == "" {
		return nil, fmt.Errorf("missing role name")
	}

	entry, err := s.Get(ctx, "role/"+name)
	if err != nil {
		return nil, err
	}

	if entry == nil {
		return nil, nil
	}

	var role alertaRoleEntry

	if err := entry.DecodeJSON(&role); err != nil {
		return nil, err
	}
	return &role, nil
}

func (b *alertaBackend) pathRolesRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	entry, err := b.getRole(ctx, req.Storage, d.Get("name").(string))
	if err != nil {
		return nil, err
	}

	if entry == nil {
		return nil, nil
	}

	return &logical.Response{
		Data: entry.toResponseData(),
	}, nil
}

func setRole(ctx context.Context, s logical.Storage, name string, roleEntry *alertaRoleEntry) error {
	entry, err := logical.StorageEntryJSON("role/"+name, roleEntry)
	if err != nil {
		return err
	}

	if entry == nil {
		return fmt.Errorf("failed to create storage entry for role")
	}

	if err := s.Put(ctx, entry); err != nil {
		return err
	}

	return nil
}

func (b *alertaBackend) pathRolesWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name, ok := d.GetOk("name")
	if !ok {
		return logical.ErrorResponse("missing role name"), nil
	}

	roleEntry, err := b.getRole(ctx, req.Storage, name.(string))
	if err != nil {
		return nil, err
	}

	if roleEntry == nil {
		roleEntry = &alertaRoleEntry{}
	}

	createOperation := (req.Operation == logical.CreateOperation)

	if user, ok := d.GetOk("user"); ok {
		roleEntry.User = user.(string)
	} else if !ok && createOperation {
		return nil, fmt.Errorf("user is required")
	}

	if scopes, ok := d.GetOk("scopes"); ok {
		roleEntry.Scopes = scopes.([]string)
	} else if !ok && createOperation {
		return nil, fmt.Errorf("scopes is required")
	}

	if description, ok := d.GetOk("description"); ok {
		roleEntry.Description = description.(string)
	} else if createOperation {
		roleEntry.Description = d.Get("description").(string)
	}

	if ttlRaw, ok := d.GetOk("ttl"); ok {
		roleEntry.TTL = time.Duration(ttlRaw.(int)) * time.Second
	} else if createOperation {
		roleEntry.TTL = time.Duration(d.Get("ttl").(int)) * time.Second
	}

	if maxTTLRaw, ok := d.GetOk("max_ttl"); ok {
		roleEntry.MaxTTL = time.Duration(maxTTLRaw.(int)) * time.Second
	} else if createOperation {
		roleEntry.MaxTTL = time.Duration(d.Get("max_ttl").(int)) * time.Second
	}

	if roleEntry.MaxTTL != 0 && roleEntry.TTL > roleEntry.MaxTTL {
		return logical.ErrorResponse("ttl cannot be greater than max_ttl"), nil
	}

	if err := setRole(ctx, req.Storage, name.(string), roleEntry); err != nil {
		return nil, err
	}

	return nil, nil
}

func (b *alertaBackend) pathRolesDelete(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	err := req.Storage.Delete(ctx, "role/"+d.Get("name").(string))
	if err != nil {
		return nil, fmt.Errorf("error deleting alerta role: %w", err)
	}

	return nil, nil
}

func (b *alertaBackend) pathRolesList(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	entries, err := req.Storage.List(ctx, "role/")
	if err != nil {
		return nil, err
	}

	return logical.ListResponse(entries), nil
}
