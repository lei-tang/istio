#!/bin/bash

kubectl delete ns istio-system
kubectl delete ns test-injection
kubectl delete ns test-validation
kubectl delete mutatingwebhookconfiguration istio-sidecar-injector
kubectl delete validatingwebhookconfiguration istio-galley

