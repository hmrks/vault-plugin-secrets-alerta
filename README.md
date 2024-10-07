# vault-plugin-secrets-alerta

## About

This is a HashiCorp Vault plugin for [Alerta](https://github.com/alerta/alerta). It is a secrets engine plugin that allows Vault to generate ephemeral Alerta API keys. This plugin is not created by, affiliated with, or supported by Alerta.

## Installation

To install the plugin, download the latest release from the [releases page](https://github.com/hmrks/vault-plugin-secrets-alerta/releases) and follow the instructions in the [Vault documentation](https://developer.hashicorp.com/vault/docs/plugins/plugin-management).

## Configuration

The plugin can be configured on the `/config` endpoint. The following configuration options are available:

* `api_url` (required) - The URL of the Alerta API.
* `auth_key` (required) - The Alerta API key used to authenticate with the Alerta API. This key must be able to create and delete API keys.

Example:
```bash
$ vault write alerta/config api_url="https://alerta.example.com/api" auth_key=12345678"
```

Next, configure a role on the `/role` endpoint. The following configuration options are available:

* `ttl` (required) - The time-to-live for the generated API key.
* `max_ttl` (required) - The maximum time-to-live for the generated API key.
* `user` (required) - The user to associate with the generated API key.
* `scopes` (required) - The scopes to associate with the generated API key.
* `description` (optional) - A description for the generated API key.

Example:
```bash
$ vault write alerta/role/my-role ttl=1h max_ttl=24h user=admin@example.com scopes="write:alerts,read:heartbeats" description="My role"
```

## Usage

Once configured, anyone with `read` access to the `alerta/keys/<role>` path can generate an API key. The generated API key will be returned as the `alerta_api_key` field in the response.

Example:
```bash
$ vault read alerta/keys/my-role

Key                  Value
---                  -----
lease_id             alerta/keys/my-role/<lease_id>
lease_duration       1h
lease_renewable      true
alerta_api_key       <alerta_api_key>
alerta_api_key_id    <alerta_api_key_id>
expire_time          2025-01-05T12:00:00Z
role_name            my-role
```

The generated API key can be used to authenticate with the Alerta API. The key will be automatically deleted when the TTL expires.

The lease can also be renewed, but only up to the maximum TTL set in the role configuration:
```bash
$ vault lease renew -increment=1h alerta/keys/my-role/<lease_id>
```

The lease can be revoked at any time:
```bash
$ vault lease revoke alerta/keys/my-role/<lease_id>
```

Once the lease is revoked, the API key will be deleted from the Alerta API.
