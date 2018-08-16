# vault-init

The `vault-init` service automates the process of [initializing](https://www.vaultproject.io/docs/commands/operator/init.html) and [unsealing](https://www.vaultproject.io/docs/concepts/seal.html#unsealing) HashiCorp Vault instances.

After `vault-init` initializes a Vault server it stores master keys and root tokens, encrypted using local storage.

## Usage

The `vault-init` service is designed to be run alongside a Vault server and communicate over local host.

## Configuration

The vault-init service supports the following environment variables for configuration:

* `VAULT_URL` - The vault URL server. It can be http://127.0.0.1:8200 or https://127.0.0.1:8200. (https://127.0.0.1:8200)
* `CHECK_INTERVAL` - The time in seconds between Vault health checks. (300)
* `BACKEND` - The backend where you should to store encrypted root token and unseal keys. Backend supported are `file-store`.
* `BACKEND_OPTIONS` - The extra parameters to set for the backend. For file-strore, you need to set `--file-path /my/path/vault.enc --encrypt-key "my very secret key"`

### Example Values

```
VAULT_URL="http://127.0.0.1:8200"
CHECK_INTERVAL="5"
BACKEND="file-store"
BACKEND_OPTIONS="--file-path /data/vault/vault.enc  --encrypt-key 2n824Y2ED1qbLFG"
```


