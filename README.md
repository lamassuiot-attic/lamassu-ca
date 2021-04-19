<a href="https://www.lamassu.io/">
  <img src="logo.png" alt="Lamassu logo" title="Lamassu" align="right" height="80" />
</a>

Lamassu
=======
[![License: MPL 2.0](https://img.shields.io/badge/License-MPL%202.0-blue.svg)](http://www.mozilla.org/MPL/2.0/index.txt)

[Lamassu](https://www.lamassu.io) project is a Public Key Infrastructure (PKI) for the Internet of Things (IoT).

## Lamassu CA
Lamassu CA is a [Vault](https://www.vaultproject.io/) API wrapper for managining the lifecycle of CAs.

## Installation
To compile Lamassu CAs wrapper follow the next steps:
1. Clone the repository and get into the application directory: `go get github.com/lamassuiot/lamassu-ca && cd src/github.com/lamassuiot/lamassu-ca/cmd`
2. Run the compilation script: `./release.sh`

The binaries will be compiled in the `/build` directory.

## Usage
The Lamassu CA wrapper should be configured with access credentials in Vault and some environment variables.

### Vault credentials
Vault authentication mode should be configured as AppRole. Once configured, the RoleID and SecretID should be provided to the wrapper as environment variables.
```
# Get AppRole RoleID
curl --header "X-Vault-Token: ${VAULT_TOKEN}" ${VAULT_ADDR}/v1/auth/approle/role/<role_name>/role-id
# Generate new Secret ID
curl --header "X-Vault-Token: ${VAULT_TOKEN}" --request POST ${VAULT_ADDR}/v1/auth/approle/role/<role_name>/secret-id
```
### Environment variables
The following environment variables should be provided.
```
CA_PORT=8087 //Wrapper API Port.
CA_VAULTADDRESS=https://vault:8200 //Vault address.
CA_VAULTROLEID=<CA_VAULTROLEID> //Vault AppRole RoleID.
CA_VAULTSECRETID=<CA_VAULTSECRETID> //Vault AppRole SecretID.
CA_VAULTCA=vault.crt //Vault server certificate CA to trust it.
CA_CERTFILE=ca.crt //Wrapper API certificate.
CA_KEYFILE=ca.key //Wrapper API key.
CA_KEYCLOAKHOSTNAME=keycloak //Keycloak server hostname.
CA_KEYCLOAKPORT=8443 //Keycloak server port.
CA_KEYCLOAKREALM=<KEYCLOAK_REALM> //Keycloak realm configured.
CA_KEYCLOAKCA=<KEYCLOAK_CA> //Keycloak server certificate CA to trust it.
CA_KEYCLOAKPROTOCOL=https //Keycloak server protocol.
CA_ENROLLERUIPROTOCOL=https //UI protocol (for CORS 'Access-Control-Allow-Origin' header).
CA_ENROLLERUIHOST=enrollerui //UI host (for CORS 'Access-Control-Allow-Origin' header).
CA_CONSULPROTOCOL=https //Consul server protocol.
CA_CONSULHOST=consul //Consul server host.
CA_CONSULCA=consul.crt //Consul server certificate CA to trust it.
CA_CONSULPORT=8501 //Consul server port.
JAEGER_SERVICE_NAME=enroller-ca //Jaeger tracing service name.
JAEGER_AGENT_HOST=jaeger //Jaeger agent host.
JAEGER_AGENT_PORT=6831 //Jaeger agent port.
```
The prefix `(CA_)` used to declare the environment variables can be changed in `cmd/main.go`:
```
cfg, err := configs.NewConfig("ca")
```
## Docker
The recommended way to run [Lamassu](https://www.lamassu.io) is following the steps explained in [lamassu-compose](https://github.com/lamassuiot/lamassu-compose) repository. However, each component can be run separately in Docker following the next steps.
```
docker image build -t lamassuiot/lamassu-ca:latest .
docker run -p 8087:8087 
  --env CA_PORT=8087
  --env CA_VAULTADDRESS=https://vault:8200
  --env CA_VAULTROLEID=<CA_VAULTROLEID>
  --env CA_VAULTSECRETID=<CA_VAULTSECRETID>
  --env CA_VAULTCA=vault.crt
  --env CA_CERTFILE=ca.crt
  --env CA_KEYFILE=ca.key
  --env CA_KEYCLOAKHOSTNAME=keycloak
  --env CA_KEYCLOAKPORT=8443
  --env CA_KEYCLOAKREALM=<KEYCLOAK_REALM>
  --env CA_KEYCLOAKCA=<KEYCLOAK_CA>
  --env CA_KEYCLOAKPROTOCOL=https
  --env CA_ENROLLERUIPROTOCOL=https
  --env CA_ENROLLERUIHOST=enrollerui
  --env CA_CONSULPROTOCOL=https
  --env CA_CONSULHOST=consul
  --env CA_CONSULCA=consul.crt
  --env CA_CONSULPORT=8501
  --env JAEGER_SERVICE_NAME=enroller-ca
  --env JAEGER_AGENT_HOST=jaeger
  --env JAEGER_AGENT_PORT=6831
  lamassuiot/lamassu-ca:latest
```
## Kubernetes
[Lamassu](https://www.lamassu.io) can be run in Kubernetes deploying the objects defined in `k8s/` directory. `provision-k8s.sh` script provides some useful guidelines and commands to deploy the objects in a local [Minikube](https://github.com/kubernetes/minikube) Kubernetes cluster.
