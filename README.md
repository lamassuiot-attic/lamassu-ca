<a href="https://www.lamassu.io/">
  <img src="logo.png" alt="Lamassu logo" title="Lamassu" align="right" height="80" />
</a>

Lamassu
=======
[![License: MPL 2.0](https://img.shields.io/badge/License-MPL%202.0-blue.svg)](http://www.mozilla.org/MPL/2.0/index.txt)

[Lamassu](https://www.lamassu.io) project is a Public Key Infrastructure (PKI) for the Internet of Things (IoT).

## Lamassu CA
Lamassu CA is a [Vault](https://www.vaultproject.io/) API wrapper for managining the lifecycle of CAs.

### Environment variables
The following environment variables shall be provided.
```
PORT=8087
PROTOCOL=https

OCSP_URL=http://ocsp.dev.lamassu.io

OIDC_WELL_KNOWN_URL=https://auth.dev.lamassu.io/auth/realms/lamassu/.well-known/openid-configuration
OIDC_CA=tls-certificates/auth/tls.crt

VAULT_ADDRESS=https://vault.dev.lamassu.io
VAULT_ROLE_ID=<vault_role_id>
VAULT_SECRET_ID=<vault_secret_id>
VAULT_CA=tls-certificates/vault/tls.crt
VAULT_PKI_CA_PATH=pki/lamassu/dev/

CERT_FILE=tls-certificates/lamassu-ca/tls.crt
KEY_FILE=tls-certificates/lamassu-ca/tls.key

JAEGER_SERVICE_NAME=ca
JAEGER_AGENT_HOST=localhost
JAEGER_AGENT_PORT=6831
JAEGER_SAMPLER_TYPE=const
JAEGER_SAMPLER_PARAM=1
JAEGER_REPORTER_LOG_SPANS=true
```

### Vault credentials
Vault authentication mode should be configured as AppRole. Once configured, the RoleID and SecretID should be provided to the wrapper as environment variables.
```
# Get AppRole RoleID
curl --header "X-Vault-Token: ${VAULT_TOKEN}" ${VAULT_ADDR}/v1/auth/approle/role/<role_name>/role-id

# Generate new Secret ID
curl --header "X-Vault-Token: ${VAULT_TOKEN}" --request POST ${VAULT_ADDR}/v1/auth/approle/role/<role_name>/secret-id
```

## Docker
The recommended way to run [Lamassu](https://www.lamassu.io) is following the steps explained in [lamassu-compose](https://github.com/lamassuiot/lamassu-compose) repository. However, each component can be run separately in Docker following the next steps.
```
docker image build -t lamassuiot/lamassu-ca:latest .
``` 
## Documentation
[Swagger](https://swagger.io/) - [OpenAPI](https://www.openapis.org/) 2.0 documentation is available in `https://ca:8087/v1/docs`. Swagger 2.0 specification JSON is created from source code annotations using [go-swagger](https://github.com/go-swagger/go-swagger) package.   
