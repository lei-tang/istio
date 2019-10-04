#!/usr/bin/env bash

# Clean up the demo
kubectl delete -f security/cmd/chiron/demo/deploy.yaml
kubectl delete secret istio-webhook-galley -n istio-system
kubectl delete secret istio-webhook-sidecar-injector -n istio-system
