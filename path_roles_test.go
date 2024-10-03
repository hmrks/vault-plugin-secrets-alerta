package alertasecrets

import (
	"context"
	"strconv"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/require"
)

const (
	roleName    = "testrole"
	user        = "test@example.com"
	description = "Test role"
	ttl         = "1h"
	max_ttl     = "1h"
)

var scopes = []string{"write:alerts"}

func TestAlertaRole(t *testing.T) {
	b, s := getTestBackend(t)

	t.Run("List All Roles", func(t *testing.T) {
		for i := 1; i <= 10; i++ {
			_, err := testAlertaRoleCreate(t, b, s,
				roleName+strconv.Itoa(i),
				map[string]interface{}{
					"user":        user,
					"scopes":      scopes,
					"description": description,
					"max_ttl":     max_ttl,
					"ttl":         ttl,
				})
			require.NoError(t, err)
		}

		resp, err := testAlertaRoleList(t, b, s)
		require.NoError(t, err)
		require.Len(t, resp.Data["keys"].([]string), 10)
	})

	t.Run("Create Alerta Role - pass", func(t *testing.T) {
		resp, err := testAlertaRoleCreate(t, b, s, roleName, map[string]interface{}{
			"user":        user,
			"scopes":      scopes,
			"description": description,
			"max_ttl":     max_ttl,
			"ttl":         ttl,
		})

		require.Nil(t, err)
		require.Nil(t, resp.Error())
		require.Nil(t, resp)
	})

	t.Run("Read Alerta Role", func(t *testing.T) {
		resp, err := testAlertaRoleRead(t, b, s)

		require.Nil(t, err)
		require.Nil(t, resp.Error())
		require.NotNil(t, resp)
		require.Equal(t, resp.Data["user"], user)
	})
	t.Run("Update Alerta Role", func(t *testing.T) {
		resp, err := testAlertaRoleUpdate(t, b, s, map[string]interface{}{
			"ttl":     "1m",
			"max_ttl": "5h",
		})

		require.Nil(t, err)
		require.Nil(t, resp.Error())
		require.Nil(t, resp)
	})

	t.Run("Re-read Alerta Role", func(t *testing.T) {
		resp, err := testAlertaRoleRead(t, b, s)

		require.Nil(t, err)
		require.Nil(t, resp.Error())
		require.NotNil(t, resp)
		require.Equal(t, resp.Data["user"], user)
	})

	t.Run("Delete Alerta Role", func(t *testing.T) {
		_, err := testAlertaRoleDelete(t, b, s)

		require.NoError(t, err)
	})
}

// Utility function to create a role while, returning any response (including errors)
func testAlertaRoleCreate(t *testing.T, b *alertaBackend, s logical.Storage, name string, d map[string]interface{}) (*logical.Response, error) {
	t.Helper()
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "role/" + name,
		Data:      d,
		Storage:   s,
	})

	if err != nil {
		return nil, err
	}

	return resp, nil
}

// Utility function to update a role while, returning any response (including errors)
func testAlertaRoleUpdate(t *testing.T, b *alertaBackend, s logical.Storage, d map[string]interface{}) (*logical.Response, error) {
	t.Helper()
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "role/" + roleName,
		Data:      d,
		Storage:   s,
	})

	if err != nil {
		return nil, err
	}

	if resp != nil && resp.IsError() {
		t.Fatal(resp.Error())
	}
	return resp, nil
}

// Utility function to read a role and return any errors
func testAlertaRoleRead(t *testing.T, b *alertaBackend, s logical.Storage) (*logical.Response, error) {
	t.Helper()
	return b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "role/" + roleName,
		Storage:   s,
	})
}

// Utility function to list roles and return any errors
func testAlertaRoleList(t *testing.T, b *alertaBackend, s logical.Storage) (*logical.Response, error) {
	t.Helper()
	return b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ListOperation,
		Path:      "role/",
		Storage:   s,
	})
}

// Utility function to delete a role and return any errors
func testAlertaRoleDelete(t *testing.T, b *alertaBackend, s logical.Storage) (*logical.Response, error) {
	t.Helper()
	return b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.DeleteOperation,
		Path:      "role/" + roleName,
		Storage:   s,
	})
}
