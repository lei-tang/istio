#!/bin/bash

# Prototyping namespace
NS=proto
kubectl create namespace $NS

# Create the service account for protovalidate webhook
kubectl create serviceaccount protovalidate -n $NS

# Create a validatingwebhookconfiguration for protovalidate
kubectl apply -f protovalidate-webhook.yaml

# Check that the validatingwebhookconfiguration is created
kubectl get validatingwebhookconfiguration protovalidate -n $NS -o yaml
