#!/usr/bin/env bash

pushd ~/go/src/istio.io/istio
git checkout chiron-demo-8-2-2019
gcloud container clusters get-credentials certificate-controller-develop-5-16-2019 --zone us-west1-b --project endpoints-authz-test1

# Build and run Chiron on linux
export HUB=gcr.io/endpoints-authz-test1
export TAG=chiron-develop-7-29-2019

# Build the image of Istio Webhook Controller
GOOS=linux GOARCH=amd64 make chiron docker.chiron; docker push gcr.io/endpoints-authz-test1/chiron:$TAG

# Build the image of a validating webhook
GOOS=linux GOARCH=amd64 make protovalidate docker.protovalidate; docker push gcr.io/endpoints-authz-test1/protovalidate:$TAG

# Build the image of a mutating webhook
GOOS=linux GOARCH=amd64  make protomutate docker.protomutate; docker push gcr.io/endpoints-authz-test1/protomutate:$TAG

##################################

# Deploy Istio Webhook Controller
kubectl create -f security/cmd/chiron/demo-deploy/deploy.yaml;

# Deploy a validating webhook, which requires a pod to have the label "must-have-label"
kubectl create -f security/cmd/protovalidate/protovalidate-deploy.yaml

# Deploy a mutating webhook, which adds an annotation "protomutate: webhook-has-patched-pod" to a pod
kubectl create -f security/cmd/protomutate/protomutate-deploy.yaml

##################################

# Demo 1: deploy a pod that demonstrates the validating webhook works with the certificate provisioned by Istio Webhook Controller
kubectl create namespace test2; kubectl label namespaces test2 protovalidate-validation=enabled; kubectl create -f security/cmd/protovalidate/example-pod.yaml -n test2
# kubectl get pod nginx -n test2 -o yaml
# The pod fails at the validation because it does not have the label
#  labels:
#    must-have-label: enabled
# gvim security/cmd/protovalidate/example-pod.yaml
# Add the label, create the pod again, the pod will pass the validation webhook
kubectl create -f security/cmd/protovalidate/example-pod.yaml -n test2

##################################

# Demo 2: deploy a pod that demonstrates the mutating webhook works with the certificate provisioned by Istio Webhook Controller
kubectl create namespace test; kubectl create -f security/cmd/protomutate/example-pod.yaml -n test
# No annotations because it is not going through mutating webhook
kubectl get pod nginx -n test -o=jsonpath='{.metadata.annotations}'; echo
kubectl label namespaces test protomutate-injection=enabled; kubectl delete -f security/cmd/protomutate/example-pod.yaml -n test; kubectl create -f security/cmd/protomutate/example-pod.yaml -n test
kubectl get pod nginx -n test -o=jsonpath='{.metadata.annotations}'; echo
# The mutating webhook should have added the annotations to the pod metadata
#  annotations:
#    protomutate: webhook-has-patched-pod

##################################

# Demo 3: Istio Webhook Controller manages the life cycle of a webhook certificate.
# If a webhook certificate is deleted, Istio Webhook Controller will recreate the webhook certificate.
kubectl get secret -n istio-system
kubectl delete secret istio.webhook.protomutate -n istio-system
kubectl get secret -n istio-system

##################################

# Demo 4: Istio Webhook Controller also manages the life cycle of a webhook configuration.
# If a webhookconfiguration is deleted, Istio Webhook Controller will recreate the webhookconfiguration.
kubectl get mutatingwebhookconfiguration -n istio-system
kubectl delete mutatingwebhookconfiguration protomutate -n istio-system
kubectl get mutatingwebhookconfiguration protomutate -n istio-system -o yaml
# If a webhookconfiguration is edited, Istio Webhook Controller will recover the webhookconfiguration
# based on the source of truth in the configmap.
kubectl edit mutatingwebhookconfiguration protomutate -n istio-system
# Change the webhook service.path to a wrong path, save, and exit.
kubectl get mutatingwebhookconfiguration protomutate -n istio-system -o yaml
# should show the webhook configuration remains the same.
##################################

# Clean up
./security/cmd/chiron/demo-scripts/cleanup.sh
