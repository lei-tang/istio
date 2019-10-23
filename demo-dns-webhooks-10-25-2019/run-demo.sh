mkdir ~/temp/demo-10-25-2019
cd ~/temp/demo-10-25-2019/
wget https://storage.googleapis.com/istio-build/dev/1.5-alpha.021a8778fb589a5da924d32bf21eccf2959e8480/istio-1.5-alpha.021a8778fb589a5da924d32bf21eccf2959e8480-osx.tar.gz
tar xfz istio-1.5-alpha.021a8778fb589a5da924d32bf21eccf2959e8480-osx.tar.gz
cd istio-1.5-alpha.021a8778fb589a5da924d32bf21eccf2959e8480/

gcloud container clusters get-credentials istio-test-10-8-2019 --zone us-central1-a --project lt-multicluster-test-1
kubectl create namespace istio-system
helm template install/kubernetes/helm/istio-init --name istio-init --namespace istio-system | kubectl apply -f -

# Open http://localhost:1313/docs/setup/install/webhook/
# View the DNS certificate configurations values-istio-dns-cert.yaml at https://raw.githubusercontent.com/istio/istio/master/install/kubernetes/helm/istio/example-values/values-istio-dns-cert.yaml
helm template \
    --name=istio \
    --namespace=istio-system \
    --set global.imagePullPolicy=Always \
    --set global.operatorManageWebhooks=true \
    --values install/kubernetes/helm/istio/example-values/values-istio-dns-cert.yaml \
    install/kubernetes/helm/istio > istio-webhook-management.yaml

kubectl apply -f istio-webhook-management.yaml

# Check that the root of webhook certificate is k8s CA, i.e.,
# the issuer of webhook certificate matches the subject of k8s CA cert.
GALLEY_POD=$(kubectl get pods --selector=app=galley -n istio-system --output=jsonpath={.items..metadata.name})
kubectl exec -it $GALLEY_POD -n istio-system -- cat /var/run/secrets/kubernetes.io/serviceaccount/ca.crt > ca.crt;  openssl x509 -text -noout -in ca.crt
# Check that webhook certificates have been generated and the issuer of webhook certificate matches the subject of k8s CA cert:
kubectl get secret dns.istio-galley-service-account -n istio-system -o json | jq -r '.data["cert-chain.pem"]' | base64 --decode > galley-cert.pem; openssl x509 -in galley-cert.pem -text -noout
kubectl get secret dns.istio-sidecar-injector-service-account -n istio-system -o json | jq -r '.data["cert-chain.pem"]' | base64 --decode > sidecar-injector-cert.pem; openssl x509 -in sidecar-injector-cert.pem -text -noout
# Check that Chiron will manage the lifecycle of a certificate, e.g., recover a deleted certificate.
kubectl delete secret dns.istio-galley-service-account -n istio-system
kubectl get secret dns.istio-galley-service-account -n istio-system -o json | jq -r '.data["cert-chain.pem"]' | base64 --decode > galley-cert.pem; openssl x509 -in galley-cert.pem -text -noout

# Demo of istioctl managing webhooks
# Check that there is no webhook configurations before running istioctl to enable webhook configurations.
kubectl get validatingwebhookconfiguration
kubectl get mutatingwebhookconfiguration

# Generate the MutatingWebhookConfiguration and ValidatingWebhookConfiguration
helm template \
    --name=istio \
    --namespace=istio-system \
    --values install/kubernetes/helm/istio/example-values/values-istio-dns-cert.yaml \
    install/kubernetes/helm/istio > istio-webhook-config.yaml

# Save the MutatingWebhookConfiguration and ValidatingWebhookConfiguration into
# sidecar-injector-webhook.yaml and galley-webhook.yaml.

# Enable webhook configurations through istioctl:
./bin/istioctl experimental post-install webhook enable --validation --webhook-secret dns.istio-galley-service-account \
    --namespace istio-system --validation-path galley-webhook.yaml \
    --injection-path sidecar-injector-webhook.yaml

# Check that webhook configurations have been configured
kubectl get validatingwebhookconfiguration
kubectl get mutatingwebhookconfiguration

# Check the Sidecar Injector webhook is working:
kubectl create namespace test-injection; kubectl label namespaces test-injection istio-injection=enabled
kubectl run --generator=run-pod/v1 --image=nginx nginx-app --port=80 -n test-injection
kubectl get pod -n test-injection
# The output should show that a sidecar container has been injected to the nginx container
# NAME        READY   STATUS    RESTARTS   AGE
# nginx-app   2/2     Running   0          10s
# If delete the webhook configuration, no sidecar container will be injected
kubectl delete mutatingwebhookconfiguration istio-sidecar-injector
kubectl create namespace test-injection-2; kubectl label namespaces test-injection-2 istio-injection=enabled
kubectl run --generator=run-pod/v1 --image=nginx nginx-app --port=80 -n test-injection-2
kubectl get pod -n test-injection-2
# NAME        READY   STATUS    RESTARTS   AGE
# nginx-app   1/1     Running   0          14s

# Check the validation webhook is working:
cat <<EOF > ./invalid-gateway.yaml
apiVersion: networking.istio.io/v1alpha3
kind: Gateway
metadata:
  name: invalid-gateway
spec:
  selector:
    # DO NOT CHANGE THESE LABELS
    # The ingressgateway is defined in install/kubernetes/helm/istio/values.yaml
    # with these labels
    istio: ingressgateway
EOF

kubectl create namespace test-validation
# The invalid gateway yaml should be rejected by the validation webhook.
kubectl apply -f invalid-gateway.yaml -n test-validation
# Expected output: Error from server: error when creating "invalid-gateway.yaml": admission webhook "pilot.validation.istio.io" denied the request: configuration is invalid: gateway must have at least one server
# If delete the webhook configuration, no validation will be done
kubectl delete validatingwebhookconfiguration istio-galley
kubectl create namespace test-validation-2
kubectl apply -f invalid-gateway.yaml -n test-validation-2
# Output: gateway.networking.istio.io/invalid-gateway created

# Enable webhooks again
./bin/istioctl experimental post-install webhook enable --validation --webhook-secret dns.istio-galley-service-account \
    --namespace istio-system --validation-path galley-webhook.yaml \
    --injection-path sidecar-injector-webhook.yaml
# Show the configurations of Galley and Sidecar Injector with their default webhook configuration names:
./bin/istioctl experimental post-install webhook status
# Show the configuration of Sidecar Injector: 
./bin/istioctl experimental post-install webhook status --validation=false
# Disable webhook configurations through istioctl:
./bin/istioctl experimental post-install webhook disable
# After disabling, no webhook configurations are configured
kubectl get validatingwebhookconfiguration
kubectl get mutatingwebhookconfiguration


