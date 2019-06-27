#!/bin/bash

# Prototyping namespace
NS=proto
kubectl create namespace $NS

# Create the service account for protomutate webhook
kubectl create serviceaccount protomutate -n $NS

# Create a mutatingwebhookconfiguration for protomutate
kubectl apply -f protomutate-webhook.yaml

# Check that the mutatingwebhookconfiguration is created
kubectl get mutatingwebhookconfiguration protomutate -n $NS -o yaml
