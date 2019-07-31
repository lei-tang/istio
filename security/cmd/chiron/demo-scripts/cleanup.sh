#!/usr/bin/env bash

# Clean up the demo
kubectl delete secret istio.webhook.protomutate -n istio-system
kubectl delete secret istio.webhook.protovalidate -n istio-system

kubectl delete mutatingwebhookconfiguration protomutate
kubectl delete validatingwebhookconfiguration protovalidate

kubectl delete -f security/cmd/chiron/demo-deploy/deploy.yaml
kubectl delete -f security/cmd/protomutate/protomutate-deploy.yaml;
kubectl delete -f security/cmd/protovalidate/protovalidate-deploy.yaml;

kubectl delete namespace test;
kubectl delete namespace test2;
