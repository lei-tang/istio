#!/usr/bin/env bash

pushd ~/go/src/istio.io/istio
git checkout chiron-standalone
gcloud container clusters get-credentials certificate-controller-develop-5-16-2019 --zone us-west1-b --project endpoints-authz-test1

# Build and run Chiron on linux
export HUB=gcr.io/endpoints-authz-test1
export TAG=chiron-develop-10-3-2019

# Build the image of Istio Webhook Controller
GOOS=linux GOARCH=amd64 make chiron docker.chiron; docker push gcr.io/endpoints-authz-test1/chiron:$TAG

##################################
# Deploy Chiron
kubectl create -f security/cmd/chiron/demo/deploy.yaml
##################################
# Demo 1: view the certificates created by Chiron.
# In particular, the DNS names in the generated certificates match those in the input parameter in
# the deployment yaml file.
kubectl get secret istio-webhook-galley  -n istio-system -o json | jq -r '.data["cert-chain.pem"]' | base64 --decode | openssl x509 -in - -text -noout
# X509v3 extensions:
#     X509v3 Basic Constraints: critical
#         CA:FALSE
#     X509v3 Subject Alternative Name:
#         DNS:istio-galley.istio-system.svc, DNS:istio-galley.istio-system
##################################
# Demo 2: Chiron recovers a deleted certificate.
kubectl delete secret istio-webhook-galley -n istio-system
kubectl get secret istio-webhook-galley  -n istio-system -o json | jq -r '.data["cert-chain.pem"]' | base64 --decode | openssl x509 -in - -text -noout
##################################
# Clean up
./security/cmd/chiron/demo/cleanup.sh
