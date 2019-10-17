#!/bin/bash

kubectl delete mutatingwebhookconfiguration istio-sidecar-injector
kubectl delete validatingwebhookconfiguration istio-galley
kubectl delete ns istio-system test-injection test-injection-2 test-validation test-validation-2

