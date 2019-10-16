# Open http://localhost:1313/docs/tasks/security/webhook/
# View the DNS certificate configurations values-istio-dns-cert.yaml at https://raw.githubusercontent.com/istio/istio/master/install/kubernetes/helm/istio/example-values/values-istio-dns-cert.yaml.

# gcloud container clusters get-credentials istio-test-10-8-2019 --zone us-central1-a --project lt-multicluster-test-1
kubectl create namespace istio-system
helm template install/kubernetes/helm/istio-init --name istio-init --namespace istio-system | kubectl apply -f -

helm template \
    --name=istio \
    --namespace=istio-system \
    --set global.operatorManageWebhooks=true \
    --values install/kubernetes/helm/istio/example-values/values-istio-dns-cert.yaml \
    install/kubernetes/helm/istio > istio-webhook-management.yaml

kubectl apply -f istio-webhook-management.yaml


# Check that the root of webhook certificate is k8s CA, i.e.,
# the issuer of webhook certificate matches the subject of k8s CA cert.
GALLEY_POD=$(kubectl get pods --selector=app=galley -n istio-system --output=jsonpath={.items..metadata.name})
kubectl exec -it $GALLEY_POD -n istio-system -- cat /var/run/secrets/kubernetes.io/serviceaccount/ca.crt > ca.crt;  openssl x509 -text -noout -in ca.crt
# Check that webhook certificates have been generated and the issuer of webhook certificate matches the subject of k8s CA cert:
kubectl get secret dns.istio-galley-service-account -n istio-system -o json | jq -r '.data["cert-chain.pem"]' | base64 --decode | openssl x509 -in - -text -noout
kubectl get secret dns.istio-sidecar-injector-service-account -n istio-system -o json | jq -r '.data["cert-chain.pem"]' | base64 --decode | openssl x509 -in - -text -noout


# Check that there is no webhook configurations before running istioctl to enable webhook configurations.
kubectl get validatingwebhookconfiguration
kubectl get mutatingwebhookconfiguration


