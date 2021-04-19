#! /bin/sh
# ==================================================================
#  _                                         
# | |                                        
# | |     __ _ _ __ ___   __ _ ___ ___ _   _ 
# | |    / _` | '_ ` _ \ / _` / __/ __| | | |
# | |___| (_| | | | | | | (_| \__ \__ \ |_| |
# |______\__,_|_| |_| |_|\__,_|___/___/\__,_|
#                                            
#                                            
# ==================================================================

minikube kubectl -- create secret generic ca-certs --from-file=./certs/consul.crt --from-file=./certs/enroller.crt --from-file=./certs/enroller.key --from-file=./certs/keycloak.crt --from-file=./certs/vault.crt
minikube kubectl -- create secret generic ca-vault-secrets --from-literal=roleid=$CA_ROLEID --from-literal=secretid=$CA_SECRETID

minikube kubectl -- apply -f k8s/ca-deployment.yml
minikube kubectl -- apply -f k8s/ca-service.yml
