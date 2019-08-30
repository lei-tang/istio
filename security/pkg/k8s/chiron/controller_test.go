// Copyright 2019 Istio Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package chiron

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"reflect"
	"testing"
	"time"

	"istio.io/istio/security/pkg/pki/ca"

	"k8s.io/api/admissionregistration/v1beta1"
	"k8s.io/apimachinery/pkg/runtime/serializer"

	"istio.io/istio/security/pkg/pki/util"

	v1 "k8s.io/api/core/v1"

	cert "k8s.io/api/certificates/v1beta1"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	runtime "k8s.io/apimachinery/pkg/runtime"

	"k8s.io/client-go/kubernetes/fake"
	kt "k8s.io/client-go/testing"
)

const (
	exampleExpiredCert = `-----BEGIN CERTIFICATE-----
MIIDXjCCAkagAwIBAgIQGbJDoVfdXBsPos+p8RGqZDANBgkqhkiG9w0BAQsFADBF
MQswCQYDVQQGEwJBVTETMBEGA1UECAwKU29tZS1TdGF0ZTEhMB8GA1UECgwYSW50
ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMB4XDTE5MDgxNjIxNDQzNVoXDTE5MDgxNjIx
NDQzNlowEzERMA8GA1UEChMISnVqdSBvcmcwggEiMA0GCSqGSIb3DQEBAQUAA4IB
DwAwggEKAoIBAQDYwh5Txh3pJVIjCt5JciYM4GMt3DsjF7E4JdVUUu682YpFevT8
rWJVaZjZajVQaT4IIYw+kxqf0hdVLJG11OHI3OeZ1IJe5yuV+STXks/+vEDMMLuD
vqWZl7oFIuXR6merPAPLAmxo0U5E9kp6ftfHJMK3uj1eNp/BZE/xH8QYe86kAckd
QYPsz0gW1YMdpxRG1OFmbih8CdbRUjCgHHPOxbAJOIDM4xtj8M1rFgVnyH+8NucW
DddKy63GASUphakC73hMnoEQksbVg6rdYlnYrdPcLgmcLeO+vdI5EjbXMaXy7GMk
JvTJI5KRAq+jPHOZmWHd2zAGUpLRPr8EFQp3AgMBAAGjfDB6MA4GA1UdDwEB/wQE
AwIFoDAMBgNVHRMBAf8EAjAAMB8GA1UdIwQYMBaAFKgUbNBCMgiPmanahMYt1KRO
dFX9MDkGA1UdEQEB/wQvMC2GK3NwaWZmZTovL2NsdXN0ZXIubG9jYWwvbnMvZGVm
YXVsdC9zYS9jbGllbnQwDQYJKoZIhvcNAQELBQADggEBAFEf0ZJnNz7h4MqGz720
0FShDX02WPmNSfl89gY/Q4/djTF5yfqgaDAZWf4PsDwpdMpT0eRrshpzvLrRjcd4
Ev6bXGncIwnNFtXQ4dseup+kmaYZF24zpRjyoH9owwu1T5Wb1cSrpFFby5xWuoTC
bsKlR5CZF+dHUwc1iMaj/4kuVjvt4imM0coeaOUzOcMCruO54IqsFcJg2YA80MI+
6UiM8hj8ERDls5iBNThWKKE0yva4HFh1gj5f427NP7CSikUFXs61gytlFHEjHyco
lK8KK65mLIDLshz2+6lPHFXv9tEpouEUws5lhR5O9Q+9LmfBLPE7rD2aUic8EApg
3TE=
-----END CERTIFICATE-----`
	// The example certificate here can be generated through
	// the following command:
	// kubectl exec -it POD-NAME -n NAMESPACE -- cat /var/run/secrets/kubernetes.io/serviceaccount/ca.crt
	// Its validity is 5 years.
	exampleCACert1 = `-----BEGIN CERTIFICATE-----
MIIDCzCCAfOgAwIBAgIQbfOzhcKTldFipQ1X2WXpHDANBgkqhkiG9w0BAQsFADAv
MS0wKwYDVQQDEyRhNzU5YzcyZC1lNjcyLTQwMzYtYWMzYy1kYzAxMDBmMTVkNWUw
HhcNMTkwNTE2MjIxMTI2WhcNMjQwNTE0MjMxMTI2WjAvMS0wKwYDVQQDEyRhNzU5
YzcyZC1lNjcyLTQwMzYtYWMzYy1kYzAxMDBmMTVkNWUwggEiMA0GCSqGSIb3DQEB
AQUAA4IBDwAwggEKAoIBAQC6sSAN80Ci0DYFpNDumGYoejMQai42g6nSKYS+ekvs
E7uT+eepO74wj8o6nFMNDu58+XgIsvPbWnn+3WtUjJfyiQXxmmTg8om4uY1C7R1H
gMsrL26pUaXZ/lTE8ZV5CnQJ9XilagY4iZKeptuZkxrWgkFBD7tr652EA3hmj+3h
4sTCQ+pBJKG8BJZDNRrCoiABYBMcFLJsaKuGZkJ6KtxhQEO9QxJVaDoSvlCRGa8R
fcVyYQyXOZ+0VHZJQgaLtqGpiQmlFttpCwDiLfMkk3UAd79ovkhN1MCq+O5N7YVt
eVQWaTUqUV2tKUFvVq21Zdl4dRaq+CF5U8uOqLY/4Kg9AgMBAAGjIzAhMA4GA1Ud
DwEB/wQEAwICBDAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQCg
oF71Ey2b1QY22C6BXcANF1+wPzxJovFeKYAnUqwh3rF7pIYCS/adZXOKlgDBsbcS
MxAGnCRi1s+A7hMYj3sQAbBXttc31557lRoJrx58IeN5DyshT53t7q4VwCzuCXFT
3zRHVRHQnO6LHgZx1FuKfwtkhfSXDyYU2fQYw2Hcb9krYU/alViVZdE0rENXCClq
xO7AQk5MJcGg6cfE5wWAKU1ATjpK4CN+RTn8v8ODLoI2SW3pfsnXxm93O+pp9HN4
+O+1PQtNUWhCfh+g6BN2mYo2OEZ8qGSxDlMZej4YOdVkW8PHmFZTK0w9iJKqM5o1
V6g5gZlqSoRhICK09tpc
-----END CERTIFICATE-----`
	exampleCACert2 = `-----BEGIN CERTIFICATE-----
MIIDDDCCAfSgAwIBAgIRALsN8ND73NbYSKTZZa4jf2EwDQYJKoZIhvcNAQELBQAw
LzEtMCsGA1UEAxMkZTNlM2RlZWQtYzIyNi00OWM2LThmOTktNDU3NmRmMzQ0YWQ1
MB4XDTE5MDYwMTE1NTU0M1oXDTI0MDUzMDE2NTU0M1owLzEtMCsGA1UEAxMkZTNl
M2RlZWQtYzIyNi00OWM2LThmOTktNDU3NmRmMzQ0YWQ1MIIBIjANBgkqhkiG9w0B
AQEFAAOCAQ8AMIIBCgKCAQEA43oeK/hS92ANjmg50LCl3tM7eYAlBB/XgCl+bfp3
KwEf+uW5yEvzSVHd2VPFI/kJJeLFrsyCRaU4FwxWcEr2Ld07DPL34oyZRRXQF0w6
4ZNSVmevBNdZLqHcoIUtR1iFJbkctE93HpGw5Kg1NXRLDu47wQtzcC3GDOEk1amu
mL916R2OcYEeOcyRDnlbLcsTYRvK5WBQsux4E0iu2Eo9GIajKmbxVLxA9fsmqG4i
/HoVkLmCg+ZRPR/66AFLPFV1J3RWp0K4HKGzBeCyd2RC+o0g8tJX3EVSuQpqzS8p
i2t71cYu/Sf5gt3wXsNHyzE6bF1o+acyzWvJlBym/HsbAQIDAQABoyMwITAOBgNV
HQ8BAf8EBAMCAgQwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEA
kJXGkFEybCp7RxUSILuIqMtKcYcQU9ulKmLSn51VrpcRHP4SH7UJ0aXMjAdRLsop
em7YgbvToGNingqcmSJlunR3jXDecSXJLUO1xcfw6N+B2BXRgUv8wV42btr2EV6q
4HKou+MnKdrQkMUx218AT8TNPBb/Yx01m8YUS7mGUTApAhBneGEcKJ8xOznIuR5v
CihWQA9AmUvfixpXNpJc4vqiYErwIXrYpuwc79SRtLuO70vV7FCctz+4JPpR7mp9
dHMZfGO1KXMbYT9P5bm+itlWSyrnn0qK/Cn5RHBoFyY91VcQJTgABS/z5O0pZ662
sNzF00Jhi0gU7th75QT3MA==
-----END CERTIFICATE-----`
)

var (
	runtimeScheme = runtime.NewScheme()
	codecs        = serializer.NewCodecFactory(runtimeScheme)
	deserializer  = codecs.UniversalDeserializer()
)

func TestNewWebhookController(t *testing.T) {
	client := fake.NewSimpleClientset()
	mutatingWebhookConfigFiles := []string{"./test-data/empty-webhook-config.yaml"}
	validatingWebhookConfigFiles := []string{"./test-data/empty-webhook-config.yaml"}

	testCases := map[string]struct {
		deleteWebhookConfigOnExit     bool
		gracePeriodRatio              float32
		minGracePeriod                time.Duration
		k8sCaCertFile                 string
		namespace                     string
		mutatingWebhookConfigFiles    []string
		mutatingWebhookConfigNames    []string
		mutatingWebhookServiceNames   []string
		mutatingWebhookServicePorts   []int
		validatingWebhookConfigFiles  []string
		validatingWebhookConfigNames  []string
		validatingWebhookServiceNames []string
		validatingWebhookServicePorts []int
		shouldFail                    bool
	}{
		"invalid grade period ratio": {
			gracePeriodRatio:             1.5,
			k8sCaCertFile:                "./test-data/example-invalid-ca-cert.pem",
			mutatingWebhookConfigFiles:   mutatingWebhookConfigFiles,
			validatingWebhookConfigFiles: validatingWebhookConfigFiles,
			shouldFail:                   true,
		},
		"invalid CA cert path": {
			gracePeriodRatio:             0.6,
			k8sCaCertFile:                "./invalid-path/invalid-file",
			mutatingWebhookConfigFiles:   mutatingWebhookConfigFiles,
			validatingWebhookConfigFiles: validatingWebhookConfigFiles,
			shouldFail:                   true,
		},
		"valid CA cert path": {
			gracePeriodRatio:             0.6,
			k8sCaCertFile:                "./test-data/example-ca-cert.pem",
			mutatingWebhookConfigFiles:   mutatingWebhookConfigFiles,
			validatingWebhookConfigFiles: validatingWebhookConfigFiles,
			shouldFail:                   false,
		},
		"invalid mutating webhook config file": {
			gracePeriodRatio:             0.6,
			k8sCaCertFile:                "./test-data/example-ca-cert.pem",
			mutatingWebhookConfigFiles:   []string{"./invalid-path/invalid-file"},
			validatingWebhookConfigFiles: validatingWebhookConfigFiles,
			shouldFail:                   true,
		},
		"invalid validatating webhook config file": {
			gracePeriodRatio:             0.6,
			k8sCaCertFile:                "./test-data/example-ca-cert.pem",
			mutatingWebhookConfigFiles:   mutatingWebhookConfigFiles,
			validatingWebhookConfigFiles: []string{"./invalid-path/invalid-file"},
			shouldFail:                   true,
		},
	}

	for _, tc := range testCases {
		wc, err := NewWebhookController(tc.deleteWebhookConfigOnExit, tc.gracePeriodRatio, tc.minGracePeriod,
			client.CoreV1(), client.AdmissionregistrationV1beta1(), client.CertificatesV1beta1(),
			tc.k8sCaCertFile, tc.namespace, tc.mutatingWebhookConfigFiles, tc.mutatingWebhookConfigNames,
			tc.mutatingWebhookServiceNames, tc.mutatingWebhookServicePorts, tc.validatingWebhookConfigFiles,
			tc.validatingWebhookConfigNames, tc.validatingWebhookServiceNames, tc.validatingWebhookServicePorts)
		if wc != nil && wc.K8sCaCertWatcher != nil {
			defer wc.K8sCaCertWatcher.Close()
		}
		if wc != nil && wc.MutatingWebhookFileWatcher != nil {
			defer wc.MutatingWebhookFileWatcher.Close()
		}
		if wc != nil && wc.ValidatingWebhookFileWatcher != nil {
			defer wc.ValidatingWebhookFileWatcher.Close()
		}
		if tc.shouldFail {
			if err == nil {
				t.Errorf("should have failed at NewWebhookController()")
			} else {
				// Should fail, skip the current case.
				continue
			}
		} else if err != nil {
			t.Errorf("should not fail at NewWebhookController(), err: %v", err)
		}
	}
}

func TestScrtDeleted(t *testing.T) {
	validatingWebhookConfigFiles := []string{"./test-data/example-validating-webhook-config.yaml"}
	mutatingWebhookConfigFiles := []string{"./test-data/empty-webhook-config.yaml"}
	mutatingWebhookConfigNames := []string{"mock-mutating-webook"}
	validatingWebhookConfigNames := []string{"mock-validating-webhook"}
	mutatingWebhookServiceNames := []string{"foo"}

	testCases := map[string]struct {
		deleteWebhookConfigOnExit     bool
		gracePeriodRatio              float32
		minGracePeriod                time.Duration
		k8sCaCertFile                 string
		namespace                     string
		mutatingWebhookConfigFiles    []string
		mutatingWebhookConfigNames    []string
		mutatingWebhookSerivceNames   []string
		mutatingWebhookSerivcePorts   []int
		validatingWebhookConfigFiles  []string
		validatingWebhookConfigNames  []string
		validatingWebhookServiceNames []string
		validatingWebhookServicePorts []int
		scrtName                      string
	}{
		"recover a deleted secret should succeed": {
			deleteWebhookConfigOnExit:    false,
			gracePeriodRatio:             0.6,
			k8sCaCertFile:                "./test-data/example-ca-cert.pem",
			namespace:                    "foo.ns",
			mutatingWebhookConfigFiles:   mutatingWebhookConfigFiles,
			mutatingWebhookConfigNames:   mutatingWebhookConfigNames,
			mutatingWebhookSerivceNames:  mutatingWebhookServiceNames,
			validatingWebhookConfigFiles: validatingWebhookConfigFiles,
			validatingWebhookConfigNames: validatingWebhookConfigNames,
			scrtName:                     "istio.webhook.foo",
		},
	}

	client := fake.NewSimpleClientset()
	csr := &cert.CertificateSigningRequest{
		ObjectMeta: metav1.ObjectMeta{
			Name: "domain-cluster.local-ns--secret-mock-secret",
		},
		Status: cert.CertificateSigningRequestStatus{
			Certificate: []byte(exampleIssuedCert),
		},
	}
	client.PrependReactor("get", "certificatesigningrequests", defaultReactionFunc(csr))

	for _, tc := range testCases {
		wc, err := NewWebhookController(tc.deleteWebhookConfigOnExit, tc.gracePeriodRatio, tc.minGracePeriod,
			client.CoreV1(), client.AdmissionregistrationV1beta1(), client.CertificatesV1beta1(),
			tc.k8sCaCertFile, tc.namespace, tc.mutatingWebhookConfigFiles, tc.mutatingWebhookConfigNames,
			tc.mutatingWebhookSerivceNames, tc.mutatingWebhookSerivcePorts, tc.validatingWebhookConfigFiles,
			tc.validatingWebhookConfigNames, tc.validatingWebhookServiceNames, tc.validatingWebhookServicePorts)
		if wc != nil && wc.K8sCaCertWatcher != nil {
			defer wc.K8sCaCertWatcher.Close()
		}
		if wc != nil && wc.MutatingWebhookFileWatcher != nil {
			defer wc.MutatingWebhookFileWatcher.Close()
		}
		if wc != nil && wc.ValidatingWebhookFileWatcher != nil {
			defer wc.ValidatingWebhookFileWatcher.Close()
		}
		if err != nil {
			t.Errorf("failed at creating webhook controller: %v", err)
			continue
		}

		_, err = client.CoreV1().Secrets(tc.namespace).Create(&v1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name: tc.scrtName,
				Labels: map[string]string{
					"secret": "for-testing",
				},
			},
		})
		if err != nil {
			t.Fatalf("failed creating test secret (%v): %v", tc.scrtName, err)
		}
		scrt, err := client.CoreV1().Secrets(tc.namespace).Get(tc.scrtName, metav1.GetOptions{})
		if err != nil || scrt == nil {
			t.Fatalf("failed to get test secret (%v): err (%v), secret (%v)", tc.scrtName, err, scrt)
		}
		err = client.CoreV1().Secrets(tc.namespace).Delete(tc.scrtName, &metav1.DeleteOptions{})
		if err != nil {
			t.Fatalf("failed deleting test secret (%v): %v", tc.scrtName, err)
		}
		_, err = client.CoreV1().Secrets(tc.namespace).Get(tc.scrtName, metav1.GetOptions{})
		if err == nil {
			t.Fatal("the deleted secret should not exist")
		}

		// The secret deleted should be recovered.
		wc.scrtDeleted(scrt)
		scrt, err = client.CoreV1().Secrets(tc.namespace).Get(tc.scrtName, metav1.GetOptions{})
		if err != nil || scrt == nil {
			t.Fatalf("after scrtDeleted(), failed to get test secret (%v): err (%v), secret (%v)",
				tc.scrtName, err, scrt)
		}
	}
}

func TestScrtUpdated(t *testing.T) {
	validatingWebhookConfigFiles := []string{"./test-data/example-validating-webhook-config.yaml"}
	mutatingWebhookConfigFiles := []string{"./test-data/empty-webhook-config.yaml"}
	mutatingWebhookConfigNames := []string{"mock-mutating-webook"}
	validatingWebhookConfigNames := []string{"mock-validating-webhook"}
	mutatingWebhookServiceNames := []string{"foo"}

	testCases := map[string]struct {
		deleteWebhookConfigOnExit     bool
		gracePeriodRatio              float32
		minGracePeriod                time.Duration
		k8sCaCertFile                 string
		namespace                     string
		mutatingWebhookConfigFiles    []string
		mutatingWebhookConfigNames    []string
		mutatingWebhookSerivceNames   []string
		mutatingWebhookSerivcePorts   []int
		validatingWebhookConfigFiles  []string
		validatingWebhookConfigNames  []string
		validatingWebhookServiceNames []string
		validatingWebhookServicePorts []int
		scrtName                      string
		changeCACert                  bool
		invalidNewSecret              bool
		replaceWithExpiredCert        bool
		expectUpdate                  bool
		newScrtName                   string
	}{
		"invalid new secret should not affect existing secret": {
			deleteWebhookConfigOnExit:    false,
			gracePeriodRatio:             0.6,
			k8sCaCertFile:                "./test-data/example-ca-cert.pem",
			namespace:                    "foo.ns",
			mutatingWebhookConfigFiles:   mutatingWebhookConfigFiles,
			mutatingWebhookConfigNames:   mutatingWebhookConfigNames,
			mutatingWebhookSerivceNames:  mutatingWebhookServiceNames,
			validatingWebhookConfigFiles: validatingWebhookConfigFiles,
			validatingWebhookConfigNames: validatingWebhookConfigNames,
			scrtName:                     "istio.webhook.foo",
			invalidNewSecret:             true,
			expectUpdate:                 false,
		},
		"non-webhook secret should not be updated": {
			deleteWebhookConfigOnExit:    false,
			gracePeriodRatio:             0.6,
			k8sCaCertFile:                "./test-data/example-ca-cert.pem",
			namespace:                    "foo.ns",
			mutatingWebhookConfigFiles:   mutatingWebhookConfigFiles,
			mutatingWebhookConfigNames:   mutatingWebhookConfigNames,
			mutatingWebhookSerivceNames:  mutatingWebhookServiceNames,
			validatingWebhookConfigFiles: validatingWebhookConfigFiles,
			validatingWebhookConfigNames: validatingWebhookConfigNames,
			scrtName:                     "istio.webhook.foo",
			newScrtName:                  "bar",
			invalidNewSecret:             false,
			expectUpdate:                 false,
		},
		"expired certificate should be updated": {
			deleteWebhookConfigOnExit:    false,
			gracePeriodRatio:             0.6,
			k8sCaCertFile:                "./test-data/example-ca-cert.pem",
			namespace:                    "foo.ns",
			mutatingWebhookConfigFiles:   mutatingWebhookConfigFiles,
			mutatingWebhookConfigNames:   mutatingWebhookConfigNames,
			mutatingWebhookSerivceNames:  mutatingWebhookServiceNames,
			validatingWebhookConfigFiles: validatingWebhookConfigFiles,
			validatingWebhookConfigNames: validatingWebhookConfigNames,
			scrtName:                     "istio.webhook.foo",
			replaceWithExpiredCert:       true,
			expectUpdate:                 true,
		},
		"changing CA certificate should lead to updating secret": {
			deleteWebhookConfigOnExit:    false,
			gracePeriodRatio:             0.6,
			k8sCaCertFile:                "./test-data/example-ca-cert.pem",
			namespace:                    "foo.ns",
			mutatingWebhookConfigFiles:   mutatingWebhookConfigFiles,
			mutatingWebhookConfigNames:   mutatingWebhookConfigNames,
			mutatingWebhookSerivceNames:  mutatingWebhookServiceNames,
			validatingWebhookConfigFiles: validatingWebhookConfigFiles,
			validatingWebhookConfigNames: validatingWebhookConfigNames,
			scrtName:                     "istio.webhook.foo",
			changeCACert:                 true,
			replaceWithExpiredCert:       false,
			expectUpdate:                 true,
		},
	}

	client := fake.NewSimpleClientset()
	csr := &cert.CertificateSigningRequest{
		ObjectMeta: metav1.ObjectMeta{
			Name: "domain-cluster.local-ns--secret-mock-secret",
		},
		Status: cert.CertificateSigningRequestStatus{
			Certificate: []byte(exampleIssuedCert),
		},
	}
	client.PrependReactor("get", "certificatesigningrequests", defaultReactionFunc(csr))

	for _, tc := range testCases {
		wc, err := NewWebhookController(tc.deleteWebhookConfigOnExit, tc.gracePeriodRatio, tc.minGracePeriod,
			client.CoreV1(), client.AdmissionregistrationV1beta1(), client.CertificatesV1beta1(),
			tc.k8sCaCertFile, tc.namespace, tc.mutatingWebhookConfigFiles, tc.mutatingWebhookConfigNames,
			tc.mutatingWebhookSerivceNames, tc.mutatingWebhookSerivcePorts, tc.validatingWebhookConfigFiles,
			tc.validatingWebhookConfigNames, tc.validatingWebhookServiceNames, tc.validatingWebhookServicePorts)
		if wc != nil && wc.K8sCaCertWatcher != nil {
			defer wc.K8sCaCertWatcher.Close()
		}
		if wc != nil && wc.MutatingWebhookFileWatcher != nil {
			defer wc.MutatingWebhookFileWatcher.Close()
		}
		if wc != nil && wc.ValidatingWebhookFileWatcher != nil {
			defer wc.ValidatingWebhookFileWatcher.Close()
		}
		if err != nil {
			t.Errorf("failed at creating webhook controller: %v", err)
			continue
		}

		err = wc.upsertSecret(tc.scrtName, tc.namespace)
		if err != nil {
			t.Errorf("should not failed at upsertSecret, err: %v", err)
		}
		scrt, err := client.CoreV1().Secrets(tc.namespace).Get(tc.scrtName, metav1.GetOptions{})
		if err != nil || scrt == nil {
			t.Fatalf("failed to get test secret (%v): err (%v), secret (%v)", tc.scrtName, err, scrt)
		}

		if tc.newScrtName != "" {
			scrt.Name = tc.newScrtName
		}
		if tc.replaceWithExpiredCert {
			scrt.Data[ca.CertChainID] = []byte(exampleExpiredCert)
		}
		if tc.changeCACert {
			scrt.Data[ca.RootCertID] = []byte(exampleCACert2)
		}

		var newScrt interface{}
		if tc.invalidNewSecret {
			// point to an invalid secret object
			newScrt = &v1.ConfigMap{}
		} else {
			newScrt = &v1.Secret{}
			scrt.DeepCopyInto(newScrt.(*v1.Secret))
		}
		wc.scrtUpdated(scrt, newScrt)

		// scrt2 is the secret after updating, which will be compared against original scrt
		scrt2, err := client.CoreV1().Secrets(tc.namespace).Get(tc.scrtName, metav1.GetOptions{})
		if err != nil || scrt2 == nil {
			t.Fatalf("failed to get test secret (%v): err (%v), secret (%v)", tc.scrtName, err, scrt2)
		}
		if tc.newScrtName != "" {
			scrt2.Name = tc.newScrtName
		}
		if tc.expectUpdate {
			if reflect.DeepEqual(scrt, scrt2) {
				t.Errorf("change is expected while there is no change")
			}
		} else {
			if !reflect.DeepEqual(scrt, scrt2) {
				t.Errorf("change is not expected while there is change")
			}
		}
	}
}

func TestRefreshSecret(t *testing.T) {
	validatingWebhookConfigFiles := []string{"./test-data/example-validating-webhook-config.yaml"}
	mutatingWebhookConfigFiles := []string{"./test-data/empty-webhook-config.yaml"}
	mutatingWebhookConfigNames := []string{"mock-mutating-webook"}
	validatingWebhookConfigNames := []string{"mock-validating-webhook"}
	mutatingWebhookServiceNames := []string{"foo"}

	testCases := map[string]struct {
		deleteWebhookConfigOnExit     bool
		gracePeriodRatio              float32
		minGracePeriod                time.Duration
		k8sCaCertFile                 string
		namespace                     string
		mutatingWebhookConfigFiles    []string
		mutatingWebhookConfigNames    []string
		mutatingWebhookSerivceNames   []string
		mutatingWebhookSerivcePorts   []int
		validatingWebhookConfigFiles  []string
		validatingWebhookConfigNames  []string
		validatingWebhookServiceNames []string
		validatingWebhookServicePorts []int
		scrtName                      string
		changeCACert                  bool
		expectUpdate                  bool
	}{
		"refresh a secret with different CA cert should succeed": {
			deleteWebhookConfigOnExit:    false,
			gracePeriodRatio:             0.6,
			k8sCaCertFile:                "./test-data/example-ca-cert.pem",
			namespace:                    "foo.ns",
			mutatingWebhookConfigFiles:   mutatingWebhookConfigFiles,
			mutatingWebhookConfigNames:   mutatingWebhookConfigNames,
			mutatingWebhookSerivceNames:  mutatingWebhookServiceNames,
			validatingWebhookConfigFiles: validatingWebhookConfigFiles,
			validatingWebhookConfigNames: validatingWebhookConfigNames,
			scrtName:                     "istio.webhook.foo",
			changeCACert:                 true,
			expectUpdate:                 true,
		},
	}

	client := fake.NewSimpleClientset()
	csr := &cert.CertificateSigningRequest{
		ObjectMeta: metav1.ObjectMeta{
			Name: "domain-cluster.local-ns--secret-mock-secret",
		},
		Status: cert.CertificateSigningRequestStatus{
			Certificate: []byte(exampleIssuedCert),
		},
	}
	client.PrependReactor("get", "certificatesigningrequests", defaultReactionFunc(csr))

	for _, tc := range testCases {
		wc, err := NewWebhookController(tc.deleteWebhookConfigOnExit, tc.gracePeriodRatio, tc.minGracePeriod,
			client.CoreV1(), client.AdmissionregistrationV1beta1(), client.CertificatesV1beta1(),
			tc.k8sCaCertFile, tc.namespace, tc.mutatingWebhookConfigFiles, tc.mutatingWebhookConfigNames,
			tc.mutatingWebhookSerivceNames, tc.mutatingWebhookSerivcePorts, tc.validatingWebhookConfigFiles,
			tc.validatingWebhookConfigNames, tc.validatingWebhookServiceNames, tc.validatingWebhookServicePorts)
		if wc != nil && wc.K8sCaCertWatcher != nil {
			defer wc.K8sCaCertWatcher.Close()
		}
		if wc != nil && wc.MutatingWebhookFileWatcher != nil {
			defer wc.MutatingWebhookFileWatcher.Close()
		}
		if wc != nil && wc.ValidatingWebhookFileWatcher != nil {
			defer wc.ValidatingWebhookFileWatcher.Close()
		}
		if err != nil {
			t.Errorf("failed at creating webhook controller: %v", err)
			continue
		}

		err = wc.upsertSecret(tc.scrtName, tc.namespace)
		if err != nil {
			t.Errorf("should not failed at upsertSecret, err: %v", err)
		}
		scrt, err := client.CoreV1().Secrets(tc.namespace).Get(tc.scrtName, metav1.GetOptions{})
		if err != nil || scrt == nil {
			t.Fatalf("failed to get test secret (%v): err (%v), secret (%v)", tc.scrtName, err, scrt)
		}

		if tc.changeCACert {
			scrt.Data[ca.RootCertID] = []byte(exampleCACert2)
		}

		newScrt := &v1.Secret{}
		scrt.DeepCopyInto(newScrt)
		err = wc.refreshSecret(newScrt)
		if err != nil {
			t.Fatalf("failed to refresh secret (%v), err: %v", newScrt, err)
		}

		// scrt2 is the secret after refreshing, which will be compared against original scrt
		scrt2, err := client.CoreV1().Secrets(tc.namespace).Get(tc.scrtName, metav1.GetOptions{})
		if err != nil || scrt2 == nil {
			t.Fatalf("failed to get test secret (%v): err (%v), secret (%v)", tc.scrtName, err, scrt2)
		}
		if tc.expectUpdate {
			if reflect.DeepEqual(scrt, scrt2) {
				t.Errorf("change is expected while there is no change")
			}
		} else {
			if !reflect.DeepEqual(scrt, scrt2) {
				t.Errorf("change is not expected while there is change")
			}
		}
	}
}

func TestCleanUpCertGen(t *testing.T) {
	validatingWebhookConfigFiles := []string{"./test-data/example-validating-webhook-config.yaml"}
	mutatingWebhookConfigFiles := []string{"./test-data/empty-webhook-config.yaml"}
	mutatingWebhookConfigNames := []string{"mock-mutating-webook"}
	validatingWebhookConfigNames := []string{"mock-validating-webhook"}
	mutatingWebhookServiceNames := []string{"foo"}

	testCases := map[string]struct {
		deleteWebhookConfigOnExit     bool
		gracePeriodRatio              float32
		minGracePeriod                time.Duration
		k8sCaCertFile                 string
		namespace                     string
		mutatingWebhookConfigFiles    []string
		mutatingWebhookConfigNames    []string
		mutatingWebhookSerivceNames   []string
		mutatingWebhookSerivcePorts   []int
		validatingWebhookConfigFiles  []string
		validatingWebhookConfigNames  []string
		validatingWebhookServiceNames []string
		validatingWebhookServicePorts []int
	}{
		"clean up a CSR should succeed": {
			deleteWebhookConfigOnExit:    false,
			gracePeriodRatio:             0.6,
			k8sCaCertFile:                "./test-data/example-ca-cert.pem",
			namespace:                    "foo.ns",
			mutatingWebhookConfigFiles:   mutatingWebhookConfigFiles,
			mutatingWebhookConfigNames:   mutatingWebhookConfigNames,
			mutatingWebhookSerivceNames:  mutatingWebhookServiceNames,
			validatingWebhookConfigFiles: validatingWebhookConfigFiles,
			validatingWebhookConfigNames: validatingWebhookConfigNames,
		},
	}

	client := fake.NewSimpleClientset()
	csrName := "test-csr"

	for _, tc := range testCases {
		wc, err := NewWebhookController(tc.deleteWebhookConfigOnExit, tc.gracePeriodRatio, tc.minGracePeriod,
			client.CoreV1(), client.AdmissionregistrationV1beta1(), client.CertificatesV1beta1(),
			tc.k8sCaCertFile, tc.namespace, tc.mutatingWebhookConfigFiles, tc.mutatingWebhookConfigNames,
			tc.mutatingWebhookSerivceNames, tc.mutatingWebhookSerivcePorts, tc.validatingWebhookConfigFiles,
			tc.validatingWebhookConfigNames, tc.validatingWebhookServiceNames, tc.validatingWebhookServicePorts)
		if wc != nil && wc.K8sCaCertWatcher != nil {
			defer wc.K8sCaCertWatcher.Close()
		}
		if wc != nil && wc.MutatingWebhookFileWatcher != nil {
			defer wc.MutatingWebhookFileWatcher.Close()
		}
		if wc != nil && wc.ValidatingWebhookFileWatcher != nil {
			defer wc.ValidatingWebhookFileWatcher.Close()
		}
		if err != nil {
			t.Fatalf("failed at creating webhook controller: %v", err)
		}

		options := util.CertOptions{
			Host:       "test-host",
			RSAKeySize: keySize,
			IsDualUse:  false,
			PKCS8Key:   false,
		}
		csrPEM, _, err := util.GenCSR(options)
		if err != nil {
			t.Fatalf("CSR generation error (%v)", err)
		}

		k8sCSR := &cert.CertificateSigningRequest{
			TypeMeta: metav1.TypeMeta{
				APIVersion: "certificates.k8s.io/v1beta1",
				Kind:       "CertificateSigningRequest",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name: csrName,
			},
			Spec: cert.CertificateSigningRequestSpec{
				Request: csrPEM,
				Groups:  []string{"system:authenticated"},
				Usages: []cert.KeyUsage{
					cert.UsageDigitalSignature,
					cert.UsageKeyEncipherment,
					cert.UsageServerAuth,
					cert.UsageClientAuth,
				},
			},
		}
		_, err = wc.certClient.CertificateSigningRequests().Create(k8sCSR)
		if err != nil {
			t.Fatalf("error when creating CSR: %v", err)
		}

		csr, err := wc.certClient.CertificateSigningRequests().Get(csrName, metav1.GetOptions{})
		if err != nil || csr == nil {
			t.Fatalf("failed to get CSR: name (%v), err (%v), CSR (%v)", csrName, err, csr)
		}

		// The CSR should be deleted.
		err = wc.cleanUpCertGen(csrName)
		if err != nil {
			t.Errorf("cleanUpCertGen returns an error: %v", err)
		}
		_, err = wc.certClient.CertificateSigningRequests().Get(csrName, metav1.GetOptions{})
		if err == nil {
			t.Fatalf("should failed at getting CSR: name (%v)", csrName)
		}
	}
}

func TestIsWebhookSecret(t *testing.T) {
	client := fake.NewSimpleClientset()
	mutatingWebhookConfigFiles := []string{"./test-data/empty-webhook-config.yaml"}
	validatingWebhookConfigFiles := []string{"./test-data/empty-webhook-config.yaml"}
	mutatingWebhookServiceNames := []string{"foo", "bar"}

	testCases := map[string]struct {
		deleteWebhookConfigOnExit     bool
		gracePeriodRatio              float32
		minGracePeriod                time.Duration
		k8sCaCertFile                 string
		namespace                     string
		mutatingWebhookConfigFiles    []string
		mutatingWebhookConfigNames    []string
		mutatingWebhookServiceNames   []string
		mutatingWebhookServicePorts   []int
		validatingWebhookConfigFiles  []string
		validatingWebhookConfigNames  []string
		validatingWebhookServiceNames []string
		validatingWebhookServicePorts []int
		scrtName                      string
		scrtNameSpace                 string
		expectedRet                   bool
	}{
		"a valid webhook secret in valid namespace": {
			gracePeriodRatio:             0.6,
			k8sCaCertFile:                "./test-data/example-ca-cert.pem",
			namespace:                    "ns.foo",
			mutatingWebhookConfigFiles:   mutatingWebhookConfigFiles,
			mutatingWebhookServiceNames:  mutatingWebhookServiceNames,
			validatingWebhookConfigFiles: validatingWebhookConfigFiles,
			scrtName:                     "istio.webhook.foo",
			scrtNameSpace:                "ns.foo",
			expectedRet:                  true,
		},
		"an invalid webhook secret in valid namespace": {
			gracePeriodRatio:             0.6,
			k8sCaCertFile:                "./test-data/example-ca-cert.pem",
			namespace:                    "ns.foo",
			mutatingWebhookConfigFiles:   mutatingWebhookConfigFiles,
			mutatingWebhookServiceNames:  mutatingWebhookServiceNames,
			validatingWebhookConfigFiles: validatingWebhookConfigFiles,
			scrtName:                     "istio.webhook.invalid",
			scrtNameSpace:                "ns.foo",
			expectedRet:                  false,
		},
		"a valid webhook secret in invalid namespace": {
			gracePeriodRatio:             0.6,
			k8sCaCertFile:                "./test-data/example-ca-cert.pem",
			namespace:                    "ns.foo",
			mutatingWebhookConfigFiles:   mutatingWebhookConfigFiles,
			mutatingWebhookServiceNames:  mutatingWebhookServiceNames,
			validatingWebhookConfigFiles: validatingWebhookConfigFiles,
			scrtName:                     "istio.webhook.foo",
			scrtNameSpace:                "ns.invalid",
			expectedRet:                  false,
		},
	}

	for _, tc := range testCases {
		wc, err := NewWebhookController(tc.deleteWebhookConfigOnExit, tc.gracePeriodRatio, tc.minGracePeriod,
			client.CoreV1(), client.AdmissionregistrationV1beta1(), client.CertificatesV1beta1(),
			tc.k8sCaCertFile, tc.namespace, tc.mutatingWebhookConfigFiles, tc.mutatingWebhookConfigNames,
			tc.mutatingWebhookServiceNames, tc.mutatingWebhookServicePorts, tc.validatingWebhookConfigFiles,
			tc.validatingWebhookConfigNames, tc.validatingWebhookServiceNames, tc.validatingWebhookServicePorts)
		if wc != nil && wc.K8sCaCertWatcher != nil {
			defer wc.K8sCaCertWatcher.Close()
		}
		if wc != nil && wc.MutatingWebhookFileWatcher != nil {
			defer wc.MutatingWebhookFileWatcher.Close()
		}
		if wc != nil && wc.ValidatingWebhookFileWatcher != nil {
			defer wc.ValidatingWebhookFileWatcher.Close()
		}
		if err != nil {
			t.Errorf("failed to create a webhook controller: %v", err)
		}

		ret := wc.isWebhookSecret(tc.scrtName, tc.scrtNameSpace)
		if tc.expectedRet != ret {
			t.Errorf("expected result (%v) differs from the actual result (%v)", tc.expectedRet, ret)
			continue
		}
	}
}

func mutateConfigReactionFunc() kt.ReactionFunc {
	return func(act kt.Action) (bool, runtime.Object, error) {
		// Do not return unrelated mutating webhook configuration
		if act.Matches("get", "mutatingwebhookconfigurations") {
			return true, nil, fmt.Errorf("unrelated mutating webhook config is not returned")
		}
		return false, nil, nil
	}
}

func TestMonitorMutatingWebhookConfigDebug(t *testing.T) {
	mutatingWebhookConfigFiles := []string{"./test-data/example-mutating-webhook-config.yaml"}
	mutatingWebhookConfigNames := []string{"protomutate"}
	mutatingWebhookServiceNames := []string{"foo"}
	validatingWebhookConfigFiles := []string{"./test-data/example-validating-webhook-config.yaml"}
	validatingWebhookConfigNames := []string{"protovalidate"}

	testCases := map[string]struct {
		deleteWebhookConfigOnExit     bool
		gracePeriodRatio              float32
		minGracePeriod                time.Duration
		k8sCaCertFile                 string
		namespace                     string
		mutatingWebhookConfigFiles    []string
		mutatingWebhookConfigNames    []string
		mutatingWebhookSerivceNames   []string
		mutatingWebhookSerivcePorts   []int
		validatingWebhookConfigFiles  []string
		validatingWebhookConfigNames  []string
		validatingWebhookServiceNames []string
		validatingWebhookServicePorts []int
		scrtName                      string

		exepceChannelSignalled bool
	}{
		//"when mutating webhook config is created, the channel should be signalled": {
		//	deleteWebhookConfigOnExit:    false,
		//	gracePeriodRatio:             0.6,
		//	k8sCaCertFile:                "./test-data/example-ca-cert.pem",
		//	namespace:                    "foo.ns",
		//	mutatingWebhookConfigFiles:   mutatingWebhookConfigFiles,
		//	mutatingWebhookConfigNames:   mutatingWebhookConfigNames,
		//	mutatingWebhookSerivceNames:  mutatingWebhookServiceNames,
		//	validatingWebhookConfigFiles: validatingWebhookConfigFiles,
		//	validatingWebhookConfigNames: validatingWebhookConfigNames,
		//	scrtName:                     "istio.webhook.foo",
		//	exepceChannelSignalled:       true,
		//},
		"when unrelated mutating webhook config is created, the channel should not be signalled": {
			deleteWebhookConfigOnExit:    false,
			gracePeriodRatio:             0.6,
			k8sCaCertFile:                "./test-data/example-ca-cert.pem",
			namespace:                    "foo.ns",
			mutatingWebhookConfigFiles:   mutatingWebhookConfigFiles,
			mutatingWebhookConfigNames:   mutatingWebhookConfigNames,
			mutatingWebhookSerivceNames:  mutatingWebhookServiceNames,
			validatingWebhookConfigFiles: validatingWebhookConfigFiles,
			validatingWebhookConfigNames: validatingWebhookConfigNames,
			scrtName:                     "istio.webhook.foo",
			exepceChannelSignalled:       false,
		},
	}

	client := fake.NewSimpleClientset()
	whName := "unrelated-webhook-config"
	client.PrependReactor("get", "mutatingwebhookconfigurations", mutateConfigReactionFunc())
	client.PrependReactor("list", "mutatingwebhookconfigurations", mutateConfigReactionFunc())

	for _, tc := range testCases {
		stopCh := make(chan struct{})
		defer close(stopCh)
		wc, err := NewWebhookController(tc.deleteWebhookConfigOnExit, tc.gracePeriodRatio, tc.minGracePeriod,
			client.CoreV1(), client.AdmissionregistrationV1beta1(), client.CertificatesV1beta1(),
			tc.k8sCaCertFile, tc.namespace, tc.mutatingWebhookConfigFiles, tc.mutatingWebhookConfigNames,
			tc.mutatingWebhookSerivceNames, tc.mutatingWebhookSerivcePorts, tc.validatingWebhookConfigFiles,
			tc.validatingWebhookConfigNames, tc.validatingWebhookServiceNames, tc.validatingWebhookServicePorts)
		if wc != nil && wc.K8sCaCertWatcher != nil {
			defer wc.K8sCaCertWatcher.Close()
		}
		if wc != nil && wc.MutatingWebhookFileWatcher != nil {
			defer wc.MutatingWebhookFileWatcher.Close()
		}
		if wc != nil && wc.ValidatingWebhookFileWatcher != nil {
			defer wc.ValidatingWebhookFileWatcher.Close()
		}
		if err != nil {
			t.Fatalf("failed at creating webhook controller: %v", err)
		}

		webhookCh := wc.monitorMutatingWebhookConfigDebug(wc.mutatingWebhookConfigNames[0], stopCh)
		if webhookCh == nil {
			t.Fatal("webhook channel returned by monitorMutatingWebhookConfigDebug is nil")
		}
		defer close(webhookCh)

		//err = wc.rebuildMutatingWebhookConfig()
		//if err != nil {
		//	t.Fatalf("failed to rebuild MutatingWebhookConfiguration: %v", err)
		//}
		//err = createOrUpdateMutatingWebhookConfig(wc)
		//if err != nil {
		//	t.Fatalf("error when creating or updating muatingwebhookconfiguration: %v", err)
		//}
		//webhookConfig := wc.mutatingWebhookConfig
		//whClient := wc.admission.MutatingWebhookConfigurations()
		//_, err = whClient.Get(webhookConfig.Name, metav1.GetOptions{})
		//if err != nil {
		//	t.Fatalf("error when getting webhook config (%v): %v", webhookConfig.Name, err)
		//}

		//webhookConfig := wc.mutatingWebhookConfig

		whClient := wc.admission.MutatingWebhookConfigurations()
		whConfig := &v1beta1.MutatingWebhookConfiguration{
			ObjectMeta: metav1.ObjectMeta{
				Name: whName,
			},
		}
		_, err = whClient.Create(whConfig)
		if err != nil {
			t.Fatalf("error when creating webhook config (%v): %v", whName, err)
		}
		//_, err = whClient.Get(whName, metav1.GetOptions{})
		//if err != nil {
		//	t.Fatalf("error when getting webhook config (%v): %v", whName, err)
		//}

		if tc.exepceChannelSignalled {
			select {
			case <-webhookCh:
			case <-time.After(2 * time.Second):
				t.Errorf("the channel is not signalled in 2 seconds")
			}
		} else {
			select {
			case <-webhookCh:
				t.Errorf("the channel should not be ignalled")
			case <-time.After(2 * time.Second):
			}
		}
	}
}

func TestWatchConfigChanges_StopChannelDebug(t *testing.T) {
	mutatingWebhookConfigFiles := []string{"./test-data/example-mutating-webhook-config.yaml"}
	mutatingWebhookConfigNames := []string{"protomutate"}
	mutatingWebhookServiceNames := []string{"foo"}
	validatingWebhookConfigFiles := []string{"./test-data/example-validating-webhook-config.yaml"}
	validatingWebhookConfigNames := []string{"protovalidate"}

	testCases := map[string]struct {
		deleteWebhookConfigOnExit     bool
		gracePeriodRatio              float32
		minGracePeriod                time.Duration
		k8sCaCertFile                 string
		namespace                     string
		mutatingWebhookConfigFiles    []string
		mutatingWebhookConfigNames    []string
		mutatingWebhookSerivceNames   []string
		mutatingWebhookSerivcePorts   []int
		validatingWebhookConfigFiles  []string
		validatingWebhookConfigNames  []string
		validatingWebhookServiceNames []string
		validatingWebhookServicePorts []int
		scrtName                      string
	}{
		"when stop, deleting webhook config should succeed": {
			deleteWebhookConfigOnExit:    true,
			gracePeriodRatio:             0.6,
			k8sCaCertFile:                "./test-data/example-ca-cert.pem",
			namespace:                    "foo.ns",
			mutatingWebhookConfigFiles:   mutatingWebhookConfigFiles,
			mutatingWebhookConfigNames:   mutatingWebhookConfigNames,
			mutatingWebhookSerivceNames:  mutatingWebhookServiceNames,
			validatingWebhookConfigFiles: validatingWebhookConfigFiles,
			validatingWebhookConfigNames: validatingWebhookConfigNames,
			scrtName:                     "istio.webhook.foo",
		},
	}

	client := fake.NewSimpleClientset()

	for _, tc := range testCases {
		stopCh := make(chan struct{})
		defer close(stopCh)
		wc, err := NewWebhookController(tc.deleteWebhookConfigOnExit, tc.gracePeriodRatio, tc.minGracePeriod,
			client.CoreV1(), client.AdmissionregistrationV1beta1(), client.CertificatesV1beta1(),
			tc.k8sCaCertFile, tc.namespace, tc.mutatingWebhookConfigFiles, tc.mutatingWebhookConfigNames,
			tc.mutatingWebhookSerivceNames, tc.mutatingWebhookSerivcePorts, tc.validatingWebhookConfigFiles,
			tc.validatingWebhookConfigNames, tc.validatingWebhookServiceNames, tc.validatingWebhookServicePorts)
		if wc != nil && wc.K8sCaCertWatcher != nil {
			defer wc.K8sCaCertWatcher.Close()
		}
		if wc != nil && wc.MutatingWebhookFileWatcher != nil {
			defer wc.MutatingWebhookFileWatcher.Close()
		}
		if wc != nil && wc.ValidatingWebhookFileWatcher != nil {
			defer wc.ValidatingWebhookFileWatcher.Close()
		}
		if err != nil {
			t.Fatalf("failed at creating webhook controller: %v", err)
		}

		err = wc.rebuildMutatingWebhookConfig()
		if err != nil {
			t.Fatalf("failed to rebuild MutatingWebhookConfiguration: %v", err)
		}
		err = createOrUpdateMutatingWebhookConfig(wc)
		if err != nil {
			t.Fatalf("error when creating or updating muatingwebhookconfiguration: %v", err)
		}
		webhookConfig := wc.mutatingWebhookConfig
		whClient := wc.admission.MutatingWebhookConfigurations()
		_, err = whClient.Get(webhookConfig.Name, metav1.GetOptions{})
		if err != nil {
			t.Fatalf("error when getting webhook config (%v): %v", webhookConfig.Name, err)
		}

		//*********** The controllers in the following two lines cause the crash problem.
		mutatingWebhookChangedCh := wc.monitorMutatingWebhookConfig(wc.mutatingWebhookConfigNames[0], stopCh)
		validatingWebhookChangedCh := wc.monitorValidatingWebhookConfig(wc.validatingWebhookConfigNames[0], stopCh)

		//wc.monitorMutatingWebhookConfig(wc.mutatingWebhookConfigNames[0], stopCh)
		//wc.monitorValidatingWebhookConfig(wc.validatingWebhookConfigNames[0], stopCh)

		// Channel signaling watchConfigChanges() completes
		done := make(chan bool)
		go func() {
			fmt.Println("call watchConfigChanges()")
			wc.watchConfigChanges(mutatingWebhookChangedCh, validatingWebhookChangedCh, stopCh)
			fmt.Println("send done signal.")
			done <- true //watchConfigChanges() completes.
		}()

		fmt.Println("send stopCh signal")
		stopCh <- struct{}{}

		fmt.Println("wait done signal")
		// Wait for watchConfigChanges() to complete
		<-done

		//After the stopCh signal is handled, the webhook configuration should have been
		//deleted when deleteWebhookConfigOnExit is true.
		_, err = whClient.Get(webhookConfig.Name, metav1.GetOptions{})
		if err == nil {
			t.Errorf("the webhook config (%v) should not exist", webhookConfig.Name)
		}
	}

	fmt.Println("wait releasing resources ...")
	// Wait for the resource is released
	//time.Sleep(200* time.Millisecond)
	fmt.Println("exit ...")
}

func TestWatchConfigChanges_ExitBySignalStopChannel(t *testing.T) {
	mutatingWebhookConfigFiles := []string{"./test-data/example-mutating-webhook-config.yaml"}
	mutatingWebhookConfigNames := []string{"protomutate"}
	mutatingWebhookServiceNames := []string{"foo"}
	validatingWebhookConfigFiles := []string{"./test-data/example-validating-webhook-config.yaml"}
	validatingWebhookConfigNames := []string{"protovalidate"}

	testCases := map[string]struct {
		deleteWebhookConfigOnExit     bool
		gracePeriodRatio              float32
		minGracePeriod                time.Duration
		k8sCaCertFile                 string
		namespace                     string
		mutatingWebhookConfigFiles    []string
		mutatingWebhookConfigNames    []string
		mutatingWebhookSerivceNames   []string
		mutatingWebhookSerivcePorts   []int
		validatingWebhookConfigFiles  []string
		validatingWebhookConfigNames  []string
		validatingWebhookServiceNames []string
		validatingWebhookServicePorts []int
		scrtName                      string
	}{
		"when stopCh is signalled, the watcher should exit": {
			deleteWebhookConfigOnExit:    false,
			gracePeriodRatio:             0.6,
			k8sCaCertFile:                "./test-data/example-ca-cert.pem",
			namespace:                    "foo.ns",
			mutatingWebhookConfigFiles:   mutatingWebhookConfigFiles,
			mutatingWebhookConfigNames:   mutatingWebhookConfigNames,
			mutatingWebhookSerivceNames:  mutatingWebhookServiceNames,
			validatingWebhookConfigFiles: validatingWebhookConfigFiles,
			validatingWebhookConfigNames: validatingWebhookConfigNames,
			scrtName:                     "istio.webhook.foo",
		},
	}

	client := fake.NewSimpleClientset()

	for _, tc := range testCases {
		stopCh := make(chan struct{})
		defer close(stopCh)
		wc, err := NewWebhookController(tc.deleteWebhookConfigOnExit, tc.gracePeriodRatio, tc.minGracePeriod,
			client.CoreV1(), client.AdmissionregistrationV1beta1(), client.CertificatesV1beta1(),
			tc.k8sCaCertFile, tc.namespace, tc.mutatingWebhookConfigFiles, tc.mutatingWebhookConfigNames,
			tc.mutatingWebhookSerivceNames, tc.mutatingWebhookSerivcePorts, tc.validatingWebhookConfigFiles,
			tc.validatingWebhookConfigNames, tc.validatingWebhookServiceNames, tc.validatingWebhookServicePorts)
		if wc != nil && wc.K8sCaCertWatcher != nil {
			defer wc.K8sCaCertWatcher.Close()
		}
		if wc != nil && wc.MutatingWebhookFileWatcher != nil {
			defer wc.MutatingWebhookFileWatcher.Close()
		}
		if wc != nil && wc.ValidatingWebhookFileWatcher != nil {
			defer wc.ValidatingWebhookFileWatcher.Close()
		}
		if err != nil {
			t.Fatalf("failed at creating webhook controller: %v", err)
		}

		mutatingWebhookChangedCh := make(chan struct{})
		validatingWebhookChangedCh := make(chan struct{})

		// Channel signaling watchConfigChanges() completes
		done := make(chan bool)
		go func() {
			wc.watchConfigChanges(mutatingWebhookChangedCh, validatingWebhookChangedCh, stopCh)
			done <- true //watchConfigChanges() completes.
		}()

		// signal stopCh
		stopCh <- struct{}{}

		// When stopCh is signalled, watchConfigChanges() should exit
		<-done
	}
}

func TestWatchConfigChanges_StopChannel(t *testing.T) {
	mutatingWebhookConfigFiles := []string{"./test-data/example-mutating-webhook-config.yaml"}
	mutatingWebhookConfigNames := []string{"protomutate"}
	mutatingWebhookServiceNames := []string{"foo"}
	validatingWebhookConfigFiles := []string{"./test-data/example-validating-webhook-config.yaml"}
	validatingWebhookConfigNames := []string{"protovalidate"}

	testCases := map[string]struct {
		deleteWebhookConfigOnExit     bool
		gracePeriodRatio              float32
		minGracePeriod                time.Duration
		k8sCaCertFile                 string
		namespace                     string
		mutatingWebhookConfigFiles    []string
		mutatingWebhookConfigNames    []string
		mutatingWebhookSerivceNames   []string
		mutatingWebhookSerivcePorts   []int
		validatingWebhookConfigFiles  []string
		validatingWebhookConfigNames  []string
		validatingWebhookServiceNames []string
		validatingWebhookServicePorts []int
		scrtName                      string
	}{
		"when stop, deleting webhook config should succeed": {
			deleteWebhookConfigOnExit:    true,
			gracePeriodRatio:             0.6,
			k8sCaCertFile:                "./test-data/example-ca-cert.pem",
			namespace:                    "foo.ns",
			mutatingWebhookConfigFiles:   mutatingWebhookConfigFiles,
			mutatingWebhookConfigNames:   mutatingWebhookConfigNames,
			mutatingWebhookSerivceNames:  mutatingWebhookServiceNames,
			validatingWebhookConfigFiles: validatingWebhookConfigFiles,
			validatingWebhookConfigNames: validatingWebhookConfigNames,
			scrtName:                     "istio.webhook.foo",
		},
	}

	client := fake.NewSimpleClientset()

	for _, tc := range testCases {
		stopCh := make(chan struct{})
		defer close(stopCh)
		wc, err := NewWebhookController(tc.deleteWebhookConfigOnExit, tc.gracePeriodRatio, tc.minGracePeriod,
			client.CoreV1(), client.AdmissionregistrationV1beta1(), client.CertificatesV1beta1(),
			tc.k8sCaCertFile, tc.namespace, tc.mutatingWebhookConfigFiles, tc.mutatingWebhookConfigNames,
			tc.mutatingWebhookSerivceNames, tc.mutatingWebhookSerivcePorts, tc.validatingWebhookConfigFiles,
			tc.validatingWebhookConfigNames, tc.validatingWebhookServiceNames, tc.validatingWebhookServicePorts)
		if wc != nil && wc.K8sCaCertWatcher != nil {
			defer wc.K8sCaCertWatcher.Close()
		}
		if wc != nil && wc.MutatingWebhookFileWatcher != nil {
			defer wc.MutatingWebhookFileWatcher.Close()
		}
		if wc != nil && wc.ValidatingWebhookFileWatcher != nil {
			defer wc.ValidatingWebhookFileWatcher.Close()
		}
		if err != nil {
			t.Fatalf("failed at creating webhook controller: %v", err)
		}

		err = wc.rebuildMutatingWebhookConfig()
		if err != nil {
			t.Fatalf("failed to rebuild MutatingWebhookConfiguration: %v", err)
		}
		err = createOrUpdateMutatingWebhookConfig(wc)
		if err != nil {
			t.Fatalf("error when creating or updating muatingwebhookconfiguration: %v", err)
		}
		webhookConfig := wc.mutatingWebhookConfig
		whClient := wc.admission.MutatingWebhookConfigurations()
		_, err = whClient.Get(webhookConfig.Name, metav1.GetOptions{})
		if err != nil {
			t.Fatalf("error when getting webhook config (%v): %v", webhookConfig.Name, err)
		}

		mutatingWebhookChangedCh := wc.monitorMutatingWebhookConfig(wc.mutatingWebhookConfigNames[0], stopCh)
		validatingWebhookChangedCh := wc.monitorValidatingWebhookConfig(wc.validatingWebhookConfigNames[0], stopCh)

		// Channel signaling watchConfigChanges() completes
		done := make(chan bool)
		go func() {
			wc.watchConfigChanges(mutatingWebhookChangedCh, validatingWebhookChangedCh, stopCh)
			done <- true //watchConfigChanges() completes.
		}()

		stopCh <- struct{}{}

		// Wait for watchConfigChanges() to complete
		<-done

		// After the stopCh signal is handled, the webhook configuration should have been
		// deleted when deleteWebhookConfigOnExit is true.
		_, err = whClient.Get(webhookConfig.Name, metav1.GetOptions{})
		if err == nil {
			t.Errorf("the webhook config (%v) should not exist", webhookConfig.Name)
		}
	}
}

func TestWatchConfigChanges_MutatingWebhookConfigChannel(t *testing.T) {
	mutatingWebhookConfigFiles := []string{"./test-data/example-mutating-webhook-config.yaml"}
	mutatingWebhookConfigNames := []string{"protomutate"}
	mutatingWebhookServiceNames := []string{"foo"}
	validatingWebhookConfigFiles := []string{"./test-data/example-validating-webhook-config.yaml"}
	validatingWebhookConfigNames := []string{"protovalidate"}

	testCases := map[string]struct {
		deleteWebhookConfigOnExit     bool
		gracePeriodRatio              float32
		minGracePeriod                time.Duration
		k8sCaCertFile                 string
		namespace                     string
		mutatingWebhookConfigFiles    []string
		mutatingWebhookConfigNames    []string
		mutatingWebhookSerivceNames   []string
		mutatingWebhookSerivcePorts   []int
		validatingWebhookConfigFiles  []string
		validatingWebhookConfigNames  []string
		validatingWebhookServiceNames []string
		validatingWebhookServicePorts []int
		scrtName                      string
	}{
		"when mutating webhook config changed, the handler watching webhook config should behave correctly": {
			deleteWebhookConfigOnExit:    false,
			gracePeriodRatio:             0.6,
			k8sCaCertFile:                "./test-data/example-ca-cert.pem",
			namespace:                    "foo.ns",
			mutatingWebhookConfigFiles:   mutatingWebhookConfigFiles,
			mutatingWebhookConfigNames:   mutatingWebhookConfigNames,
			mutatingWebhookSerivceNames:  mutatingWebhookServiceNames,
			validatingWebhookConfigFiles: validatingWebhookConfigFiles,
			validatingWebhookConfigNames: validatingWebhookConfigNames,
			scrtName:                     "istio.webhook.foo",
		},
	}

	client := fake.NewSimpleClientset()

	for _, tc := range testCases {
		stopCh := make(chan struct{})
		defer close(stopCh)
		wc, err := NewWebhookController(tc.deleteWebhookConfigOnExit, tc.gracePeriodRatio, tc.minGracePeriod,
			client.CoreV1(), client.AdmissionregistrationV1beta1(), client.CertificatesV1beta1(),
			tc.k8sCaCertFile, tc.namespace, tc.mutatingWebhookConfigFiles, tc.mutatingWebhookConfigNames,
			tc.mutatingWebhookSerivceNames, tc.mutatingWebhookSerivcePorts, tc.validatingWebhookConfigFiles,
			tc.validatingWebhookConfigNames, tc.validatingWebhookServiceNames, tc.validatingWebhookServicePorts)
		if wc != nil && wc.K8sCaCertWatcher != nil {
			defer wc.K8sCaCertWatcher.Close()
		}
		if wc != nil && wc.MutatingWebhookFileWatcher != nil {
			defer wc.MutatingWebhookFileWatcher.Close()
		}
		if wc != nil && wc.ValidatingWebhookFileWatcher != nil {
			defer wc.ValidatingWebhookFileWatcher.Close()
		}
		if err != nil {
			t.Fatalf("failed at creating webhook controller: %v", err)
		}

		err = wc.rebuildMutatingWebhookConfig()
		if err != nil {
			t.Fatalf("failed to rebuild MutatingWebhookConfiguration: %v", err)
		}
		err = createOrUpdateMutatingWebhookConfig(wc)
		if err != nil {
			t.Fatalf("error when creating or updating muatingwebhookconfiguration: %v", err)
		}
		webhookConfig := wc.mutatingWebhookConfig
		whClient := wc.admission.MutatingWebhookConfigurations()
		_, err = whClient.Get(webhookConfig.Name, metav1.GetOptions{})
		if err != nil {
			t.Fatalf("error when getting webhook config (%v): %v", webhookConfig.Name, err)
		}

		mutatingWebhookChangedCh := wc.monitorMutatingWebhookConfig(wc.mutatingWebhookConfigNames[0], stopCh)
		validatingWebhookChangedCh := wc.monitorValidatingWebhookConfig(wc.validatingWebhookConfigNames[0], stopCh)

		// Channel signaling watchConfigChanges() completes
		done := make(chan bool)
		go func() {
			wc.watchConfigChanges(mutatingWebhookChangedCh, validatingWebhookChangedCh, stopCh)
			done <- true //watchConfigChanges() completes.
		}()

		// Delete the webhook configuration, which will be recovered by the handler.
		err = whClient.Delete(webhookConfig.Name, &metav1.DeleteOptions{})
		if err != nil {
			t.Fatalf("error when deleting the webhook config (%v): %v", webhookConfig.Name, err)
		}
		mutatingWebhookChangedCh <- struct{}{}

		stopCh <- struct{}{}
		// Wait for watchConfigChanges() to complete
		<-done

		_, err = whClient.Get(webhookConfig.Name, metav1.GetOptions{})
		if err != nil {
			t.Errorf("the webhook config (%v) should have been recovered: %v", webhookConfig.Name, err)
		}
	}
}

func TestWatchConfigChanges_ValidatingWebhookConfigChannel(t *testing.T) {
	mutatingWebhookConfigFiles := []string{"./test-data/example-mutating-webhook-config.yaml"}
	mutatingWebhookConfigNames := []string{"protomutate"}
	validatingWebhookConfigFiles := []string{"./test-data/example-validating-webhook-config.yaml"}
	validatingWebhookConfigNames := []string{"protovalidate"}
	validatingWebhookServiceNames := []string{"foo"}

	testCases := map[string]struct {
		deleteWebhookConfigOnExit     bool
		gracePeriodRatio              float32
		minGracePeriod                time.Duration
		k8sCaCertFile                 string
		namespace                     string
		mutatingWebhookConfigFiles    []string
		mutatingWebhookConfigNames    []string
		mutatingWebhookSerivceNames   []string
		mutatingWebhookSerivcePorts   []int
		validatingWebhookConfigFiles  []string
		validatingWebhookConfigNames  []string
		validatingWebhookServiceNames []string
		validatingWebhookServicePorts []int
		scrtName                      string
	}{
		"when validating webhook config changed, the handler watching webhook config should behave correctly": {
			deleteWebhookConfigOnExit:     false,
			gracePeriodRatio:              0.6,
			k8sCaCertFile:                 "./test-data/example-ca-cert.pem",
			namespace:                     "foo.ns",
			mutatingWebhookConfigFiles:    mutatingWebhookConfigFiles,
			mutatingWebhookConfigNames:    mutatingWebhookConfigNames,
			validatingWebhookConfigFiles:  validatingWebhookConfigFiles,
			validatingWebhookConfigNames:  validatingWebhookConfigNames,
			validatingWebhookServiceNames: validatingWebhookServiceNames,
			scrtName:                      "istio.webhook.foo",
		},
	}

	client := fake.NewSimpleClientset()

	for _, tc := range testCases {
		stopCh := make(chan struct{})
		defer close(stopCh)
		wc, err := NewWebhookController(tc.deleteWebhookConfigOnExit, tc.gracePeriodRatio, tc.minGracePeriod,
			client.CoreV1(), client.AdmissionregistrationV1beta1(), client.CertificatesV1beta1(),
			tc.k8sCaCertFile, tc.namespace, tc.mutatingWebhookConfigFiles, tc.mutatingWebhookConfigNames,
			tc.mutatingWebhookSerivceNames, tc.mutatingWebhookSerivcePorts, tc.validatingWebhookConfigFiles,
			tc.validatingWebhookConfigNames, tc.validatingWebhookServiceNames, tc.validatingWebhookServicePorts)
		if wc != nil && wc.K8sCaCertWatcher != nil {
			defer wc.K8sCaCertWatcher.Close()
		}
		if wc != nil && wc.MutatingWebhookFileWatcher != nil {
			defer wc.MutatingWebhookFileWatcher.Close()
		}
		if wc != nil && wc.ValidatingWebhookFileWatcher != nil {
			defer wc.ValidatingWebhookFileWatcher.Close()
		}
		if err != nil {
			t.Fatalf("failed at creating webhook controller: %v", err)
		}

		err = wc.rebuildValidatingWebhookConfig()
		if err != nil {
			t.Fatalf("failed to rebuild ValidatingWebhookConfiguration: %v", err)
		}
		err = createOrUpdateValidatingWebhookConfig(wc)
		if err != nil {
			t.Fatalf("error when creating or updating validatingwebhookconfiguration: %v", err)
		}
		webhookConfig := wc.validatingWebhookConfig
		whClient := wc.admission.ValidatingWebhookConfigurations()
		_, err = whClient.Get(webhookConfig.Name, metav1.GetOptions{})
		if err != nil {
			t.Fatalf("error when getting webhook config (%v): %v", webhookConfig.Name, err)
		}

		mutatingWebhookChangedCh := wc.monitorMutatingWebhookConfig(wc.mutatingWebhookConfigNames[0], stopCh)
		validatingWebhookChangedCh := wc.monitorValidatingWebhookConfig(wc.validatingWebhookConfigNames[0], stopCh)

		// Channel signaling watchConfigChanges() completes
		done := make(chan bool)
		go func() {
			wc.watchConfigChanges(mutatingWebhookChangedCh, validatingWebhookChangedCh, stopCh)
			done <- true //watchConfigChanges() completes.
		}()

		// Delete the webhook configuration, which will be recovered by the handler.
		err = whClient.Delete(webhookConfig.Name, &metav1.DeleteOptions{})
		if err != nil {
			t.Fatalf("error when deleting the webhook config (%v): %v", webhookConfig.Name, err)
		}
		validatingWebhookChangedCh <- struct{}{}

		stopCh <- struct{}{}
		// Wait for watchConfigChanges() to complete
		<-done

		_, err = whClient.Get(webhookConfig.Name, metav1.GetOptions{})
		if err != nil {
			t.Errorf("the webhook config (%v) should have been recovered: %v", webhookConfig.Name, err)
		}
	}
}

func TestRebuildMutatingWebhookConfig(t *testing.T) {
	mutatingWebhookConfigFiles := []string{"./test-data/example-mutating-webhook-config.yaml"}
	mutatingWebhookConfigNames := []string{"protomutate"}
	mutatingWebhookServiceNames := []string{"foo"}
	validatingWebhookConfigFiles := []string{"./test-data/example-validating-webhook-config.yaml"}
	validatingWebhookConfigNames := []string{"protovalidate"}

	testCases := map[string]struct {
		deleteWebhookConfigOnExit     bool
		gracePeriodRatio              float32
		minGracePeriod                time.Duration
		k8sCaCertFile                 string
		namespace                     string
		mutatingWebhookConfigFiles    []string
		mutatingWebhookConfigNames    []string
		mutatingWebhookSerivceNames   []string
		mutatingWebhookSerivcePorts   []int
		validatingWebhookConfigFiles  []string
		validatingWebhookConfigNames  []string
		validatingWebhookServiceNames []string
		validatingWebhookServicePorts []int
	}{
		"rebuildMutatingWebhookConfig should succeed": {
			deleteWebhookConfigOnExit:    false,
			gracePeriodRatio:             0.6,
			k8sCaCertFile:                "./test-data/example-ca-cert.pem",
			namespace:                    "foo.ns",
			mutatingWebhookConfigFiles:   mutatingWebhookConfigFiles,
			mutatingWebhookConfigNames:   mutatingWebhookConfigNames,
			mutatingWebhookSerivceNames:  mutatingWebhookServiceNames,
			validatingWebhookConfigFiles: validatingWebhookConfigFiles,
			validatingWebhookConfigNames: validatingWebhookConfigNames,
		},
	}

	client := fake.NewSimpleClientset()

	for _, tc := range testCases {
		wc, err := NewWebhookController(tc.deleteWebhookConfigOnExit, tc.gracePeriodRatio, tc.minGracePeriod,
			client.CoreV1(), client.AdmissionregistrationV1beta1(), client.CertificatesV1beta1(),
			tc.k8sCaCertFile, tc.namespace, tc.mutatingWebhookConfigFiles, tc.mutatingWebhookConfigNames,
			tc.mutatingWebhookSerivceNames, tc.mutatingWebhookSerivcePorts, tc.validatingWebhookConfigFiles,
			tc.validatingWebhookConfigNames, tc.validatingWebhookServiceNames, tc.validatingWebhookServicePorts)
		if wc != nil && wc.K8sCaCertWatcher != nil {
			defer wc.K8sCaCertWatcher.Close()
		}
		if wc != nil && wc.MutatingWebhookFileWatcher != nil {
			defer wc.MutatingWebhookFileWatcher.Close()
		}
		if wc != nil && wc.ValidatingWebhookFileWatcher != nil {
			defer wc.ValidatingWebhookFileWatcher.Close()
		}
		if err != nil {
			t.Fatalf("failed at creating webhook controller: %v", err)
		}

		err = wc.rebuildMutatingWebhookConfig()
		if err != nil {
			t.Fatalf("failed to rebuild MutatingWebhookConfiguration: %v", err)
		}

		config := v1beta1.MutatingWebhookConfiguration{}
		rb, err := ioutil.ReadFile("./test-data/example-mutating-webhook-config.yaml")
		if err != nil {
			t.Fatalf("error reading example mutating webhook config: %v ", err)
		}
		_, _, err = deserializer.Decode(rb, nil, &config)
		if err != nil || len(config.Webhooks) != 1 {
			t.Fatalf("failed to decode example MutatingWebhookConfiguration: %v", err)
		}
		rb, err = ioutil.ReadFile("./test-data/example-ca-cert.pem")
		if err != nil {
			t.Fatalf("error reading example certificate file: %v ", err)
		}
		config.Webhooks[0].ClientConfig.CABundle = rb
		if !reflect.DeepEqual(&config, wc.mutatingWebhookConfig) {
			t.Errorf("the MutatingWebhookConfiguration is unexpected,"+
				"expected: %v, actual: %v", config, wc.mutatingWebhookConfig)
		}
	}
}

func TestRebuildValidatingWebhookConfig(t *testing.T) {
	mutatingWebhookConfigFiles := []string{"./test-data/example-mutating-webhook-config.yaml"}
	mutatingWebhookConfigNames := []string{"protomutate"}
	validatingWebhookServiceNames := []string{"foo"}
	validatingWebhookConfigFiles := []string{"./test-data/example-validating-webhook-config.yaml"}
	validatingWebhookConfigNames := []string{"protovalidate"}

	testCases := map[string]struct {
		deleteWebhookConfigOnExit     bool
		gracePeriodRatio              float32
		minGracePeriod                time.Duration
		k8sCaCertFile                 string
		namespace                     string
		mutatingWebhookConfigFiles    []string
		mutatingWebhookConfigNames    []string
		mutatingWebhookSerivceNames   []string
		mutatingWebhookSerivcePorts   []int
		validatingWebhookConfigFiles  []string
		validatingWebhookConfigNames  []string
		validatingWebhookServiceNames []string
		validatingWebhookServicePorts []int
	}{
		"rebuildMutatingWebhookConfig should succeed": {
			deleteWebhookConfigOnExit:     false,
			gracePeriodRatio:              0.6,
			k8sCaCertFile:                 "./test-data/example-ca-cert.pem",
			namespace:                     "foo.ns",
			mutatingWebhookConfigFiles:    mutatingWebhookConfigFiles,
			mutatingWebhookConfigNames:    mutatingWebhookConfigNames,
			validatingWebhookConfigFiles:  validatingWebhookConfigFiles,
			validatingWebhookConfigNames:  validatingWebhookConfigNames,
			validatingWebhookServiceNames: validatingWebhookServiceNames,
		},
	}

	client := fake.NewSimpleClientset()

	for _, tc := range testCases {
		wc, err := NewWebhookController(tc.deleteWebhookConfigOnExit, tc.gracePeriodRatio, tc.minGracePeriod,
			client.CoreV1(), client.AdmissionregistrationV1beta1(), client.CertificatesV1beta1(),
			tc.k8sCaCertFile, tc.namespace, tc.mutatingWebhookConfigFiles, tc.mutatingWebhookConfigNames,
			tc.mutatingWebhookSerivceNames, tc.mutatingWebhookSerivcePorts, tc.validatingWebhookConfigFiles,
			tc.validatingWebhookConfigNames, tc.validatingWebhookServiceNames, tc.validatingWebhookServicePorts)
		if wc != nil && wc.K8sCaCertWatcher != nil {
			defer wc.K8sCaCertWatcher.Close()
		}
		if wc != nil && wc.MutatingWebhookFileWatcher != nil {
			defer wc.MutatingWebhookFileWatcher.Close()
		}
		if wc != nil && wc.ValidatingWebhookFileWatcher != nil {
			defer wc.ValidatingWebhookFileWatcher.Close()
		}
		if err != nil {
			t.Fatalf("failed at creating webhook controller: %v", err)
		}

		err = wc.rebuildValidatingWebhookConfig()
		if err != nil {
			t.Fatalf("failed to rebuild ValidatingWebhookConfiguration: %v", err)
		}

		config := v1beta1.ValidatingWebhookConfiguration{}
		rb, err := ioutil.ReadFile("./test-data/example-validating-webhook-config.yaml")
		if err != nil {
			t.Fatalf("error reading example validating webhook config: %v ", err)
		}
		_, _, err = deserializer.Decode(rb, nil, &config)
		if err != nil || len(config.Webhooks) != 1 {
			t.Fatalf("failed to decode example ValidatingWebhookConfiguration: %v", err)
		}
		rb, err = ioutil.ReadFile("./test-data/example-ca-cert.pem")
		if err != nil {
			t.Fatalf("error reading example certificate file: %v ", err)
		}
		config.Webhooks[0].ClientConfig.CABundle = rb
		if !reflect.DeepEqual(&config, wc.validatingWebhookConfig) {
			t.Errorf("the ValidaingWebhookConfiguration is unexpected,"+
				"expected: %v, actual: %v", config, wc.validatingWebhookConfig)
		}
	}
}

func TestGetCACert(t *testing.T) {
	validatingWebhookConfigFiles := []string{"./test-data/example-validating-webhook-config.yaml"}
	mutatingWebhookConfigFiles := []string{"./test-data/empty-webhook-config.yaml"}
	mutatingWebhookConfigNames := []string{"mock-mutating-webook"}
	validatingWebhookConfigNames := []string{"mock-validating-webhook"}
	mutatingWebhookServiceNames := []string{"foo"}

	testCases := map[string]struct {
		deleteWebhookConfigOnExit     bool
		gracePeriodRatio              float32
		minGracePeriod                time.Duration
		k8sCaCertFile                 string
		namespace                     string
		mutatingWebhookConfigFiles    []string
		mutatingWebhookConfigNames    []string
		mutatingWebhookSerivceNames   []string
		mutatingWebhookSerivcePorts   []int
		validatingWebhookConfigFiles  []string
		validatingWebhookConfigNames  []string
		validatingWebhookServiceNames []string
		validatingWebhookServicePorts []int
		expectFail                    bool
	}{
		"getCACert should succeed for a valid certificate": {
			deleteWebhookConfigOnExit:    false,
			gracePeriodRatio:             0.6,
			k8sCaCertFile:                "./test-data/example-ca-cert.pem",
			namespace:                    "foo.ns",
			mutatingWebhookConfigFiles:   mutatingWebhookConfigFiles,
			mutatingWebhookConfigNames:   mutatingWebhookConfigNames,
			mutatingWebhookSerivceNames:  mutatingWebhookServiceNames,
			validatingWebhookConfigFiles: validatingWebhookConfigFiles,
			validatingWebhookConfigNames: validatingWebhookConfigNames,
			expectFail:                   false,
		},
	}

	client := fake.NewSimpleClientset()

	for _, tc := range testCases {
		// If the CA cert. is invalid, NewWebhookController will fail.
		wc, err := NewWebhookController(tc.deleteWebhookConfigOnExit, tc.gracePeriodRatio, tc.minGracePeriod,
			client.CoreV1(), client.AdmissionregistrationV1beta1(), client.CertificatesV1beta1(),
			tc.k8sCaCertFile, tc.namespace, tc.mutatingWebhookConfigFiles, tc.mutatingWebhookConfigNames,
			tc.mutatingWebhookSerivceNames, tc.mutatingWebhookSerivcePorts, tc.validatingWebhookConfigFiles,
			tc.validatingWebhookConfigNames, tc.validatingWebhookServiceNames, tc.validatingWebhookServicePorts)
		if wc != nil && wc.K8sCaCertWatcher != nil {
			defer wc.K8sCaCertWatcher.Close()
		}
		if wc != nil && wc.MutatingWebhookFileWatcher != nil {
			defer wc.MutatingWebhookFileWatcher.Close()
		}
		if wc != nil && wc.ValidatingWebhookFileWatcher != nil {
			defer wc.ValidatingWebhookFileWatcher.Close()
		}
		if err != nil {
			t.Fatalf("failed at creating webhook controller: %v", err)
		}

		cert, err := wc.getCACert()
		if !tc.expectFail {
			if err != nil {
				t.Errorf("failed to get CA cert: %v", err)
			} else if !bytes.Equal(cert, []byte(exampleCACert1)) {
				t.Errorf("the CA certificate read does not match the actual certificate")
			}
		} else if err == nil {
			t.Error("expect failure on getting CA cert but succeeded")
		}
	}
}

func TestUpsertSecret(t *testing.T) {
	validatingWebhookConfigFiles := []string{"./test-data/example-validating-webhook-config.yaml"}
	mutatingWebhookConfigFiles := []string{"./test-data/empty-webhook-config.yaml"}
	mutatingWebhookConfigNames := []string{"mock-mutating-webook"}
	validatingWebhookConfigNames := []string{"mock-validating-webhook"}
	mutatingWebhookServiceNames := []string{"foo"}

	testCases := map[string]struct {
		deleteWebhookConfigOnExit     bool
		gracePeriodRatio              float32
		minGracePeriod                time.Duration
		k8sCaCertFile                 string
		namespace                     string
		mutatingWebhookConfigFiles    []string
		mutatingWebhookConfigNames    []string
		mutatingWebhookSerivceNames   []string
		mutatingWebhookSerivcePorts   []int
		validatingWebhookConfigFiles  []string
		validatingWebhookConfigNames  []string
		validatingWebhookServiceNames []string
		validatingWebhookServicePorts []int
		scrtName                      string
		expectFaill                   bool
	}{
		"upsert a valid secret name should succeed": {
			deleteWebhookConfigOnExit:    false,
			gracePeriodRatio:             0.6,
			k8sCaCertFile:                "./test-data/example-ca-cert.pem",
			namespace:                    "foo.ns",
			mutatingWebhookConfigFiles:   mutatingWebhookConfigFiles,
			mutatingWebhookConfigNames:   mutatingWebhookConfigNames,
			mutatingWebhookSerivceNames:  mutatingWebhookServiceNames,
			validatingWebhookConfigFiles: validatingWebhookConfigFiles,
			validatingWebhookConfigNames: validatingWebhookConfigNames,
			scrtName:                     "istio.webhook.foo",
			expectFaill:                  false,
		},
		"upsert an invalid secret name should fail": {
			deleteWebhookConfigOnExit:    false,
			gracePeriodRatio:             0.6,
			k8sCaCertFile:                "./test-data/example-ca-cert.pem",
			namespace:                    "bar.ns",
			mutatingWebhookConfigFiles:   mutatingWebhookConfigFiles,
			mutatingWebhookConfigNames:   mutatingWebhookConfigNames,
			mutatingWebhookSerivceNames:  mutatingWebhookServiceNames,
			validatingWebhookConfigFiles: validatingWebhookConfigFiles,
			validatingWebhookConfigNames: validatingWebhookConfigNames,
			scrtName:                     "istio.webhook.bar",
			expectFaill:                  true,
		},
	}

	client := fake.NewSimpleClientset()
	csr := &cert.CertificateSigningRequest{
		ObjectMeta: metav1.ObjectMeta{
			Name: "domain-cluster.local-ns--secret-mock-secret",
		},
		Status: cert.CertificateSigningRequestStatus{
			Certificate: []byte(exampleIssuedCert),
		},
	}
	client.PrependReactor("get", "certificatesigningrequests", defaultReactionFunc(csr))

	for _, tc := range testCases {
		wc, err := NewWebhookController(tc.deleteWebhookConfigOnExit, tc.gracePeriodRatio, tc.minGracePeriod,
			client.CoreV1(), client.AdmissionregistrationV1beta1(), client.CertificatesV1beta1(),
			tc.k8sCaCertFile, tc.namespace, tc.mutatingWebhookConfigFiles, tc.mutatingWebhookConfigNames,
			tc.mutatingWebhookSerivceNames, tc.mutatingWebhookSerivcePorts, tc.validatingWebhookConfigFiles,
			tc.validatingWebhookConfigNames, tc.validatingWebhookServiceNames, tc.validatingWebhookServicePorts)
		if wc != nil && wc.K8sCaCertWatcher != nil {
			defer wc.K8sCaCertWatcher.Close()
		}
		if wc != nil && wc.MutatingWebhookFileWatcher != nil {
			defer wc.MutatingWebhookFileWatcher.Close()
		}
		if wc != nil && wc.ValidatingWebhookFileWatcher != nil {
			defer wc.ValidatingWebhookFileWatcher.Close()
		}
		if err != nil {
			t.Errorf("failed at creating webhook controller: %v", err)
			continue
		}

		err = wc.upsertSecret(tc.scrtName, tc.namespace)
		if tc.expectFaill {
			if err == nil {
				t.Errorf("should have failed at upsertSecret")
			}
			continue
		} else if err != nil {
			t.Errorf("should not failed at upsertSecret, err: %v", err)
		}
	}
}

func TestGetServiceName(t *testing.T) {
	client := fake.NewSimpleClientset()
	mutatingWebhookConfigFiles := []string{"./test-data/empty-webhook-config.yaml"}
	validatingWebhookConfigFiles := []string{"./test-data/empty-webhook-config.yaml"}
	mutatingWebhookServiceNames := []string{"foo", "bar"}
	validatingWebhookServiceNames := []string{"baz"}

	testCases := map[string]struct {
		deleteWebhookConfigOnExit     bool
		gracePeriodRatio              float32
		minGracePeriod                time.Duration
		k8sCaCertFile                 string
		namespace                     string
		mutatingWebhookConfigFiles    []string
		mutatingWebhookConfigNames    []string
		mutatingWebhookServiceNames   []string
		mutatingWebhookServicePorts   []int
		validatingWebhookConfigFiles  []string
		validatingWebhookConfigNames  []string
		validatingWebhookServiceNames []string
		validatingWebhookServicePorts []int
		scrtName                      string
		expectFound                   bool
		expectedSvcName               string
	}{
		"a mutating webhook service corresponding to a secret exists": {
			gracePeriodRatio:             0.6,
			k8sCaCertFile:                "./test-data/example-ca-cert.pem",
			mutatingWebhookConfigFiles:   mutatingWebhookConfigFiles,
			mutatingWebhookServiceNames:  mutatingWebhookServiceNames,
			validatingWebhookConfigFiles: validatingWebhookConfigFiles,
			scrtName:                     "istio.webhook.foo",
			expectFound:                  true,
			expectedSvcName:              "foo",
		},
		"a mutating service corresponding to a secret does not exists": {
			gracePeriodRatio:             0.6,
			k8sCaCertFile:                "./test-data/example-ca-cert.pem",
			mutatingWebhookConfigFiles:   mutatingWebhookConfigFiles,
			mutatingWebhookServiceNames:  mutatingWebhookServiceNames,
			validatingWebhookConfigFiles: validatingWebhookConfigFiles,
			scrtName:                     "istio.webhook.baz",
			expectFound:                  false,
			expectedSvcName:              "foo",
		},
		"a validating webhook service corresponding to a secret exists": {
			gracePeriodRatio:              0.6,
			k8sCaCertFile:                 "./test-data/example-ca-cert.pem",
			mutatingWebhookConfigFiles:    mutatingWebhookConfigFiles,
			mutatingWebhookServiceNames:   mutatingWebhookServiceNames,
			validatingWebhookConfigFiles:  validatingWebhookConfigFiles,
			validatingWebhookServiceNames: validatingWebhookServiceNames,
			scrtName:                      "istio.webhook.baz",
			expectFound:                   true,
			expectedSvcName:               "baz",
		},
		"a validating webhook service corresponding to a secret does not exists": {
			gracePeriodRatio:              0.6,
			k8sCaCertFile:                 "./test-data/example-ca-cert.pem",
			mutatingWebhookConfigFiles:    mutatingWebhookConfigFiles,
			mutatingWebhookServiceNames:   mutatingWebhookServiceNames,
			validatingWebhookConfigFiles:  validatingWebhookConfigFiles,
			validatingWebhookServiceNames: validatingWebhookServiceNames,
			scrtName:                      "istio.webhook.barr",
			expectFound:                   false,
			expectedSvcName:               "bar",
		},
	}

	for _, tc := range testCases {
		wc, err := NewWebhookController(tc.deleteWebhookConfigOnExit, tc.gracePeriodRatio, tc.minGracePeriod,
			client.CoreV1(), client.AdmissionregistrationV1beta1(), client.CertificatesV1beta1(),
			tc.k8sCaCertFile, tc.namespace, tc.mutatingWebhookConfigFiles, tc.mutatingWebhookConfigNames,
			tc.mutatingWebhookServiceNames, tc.mutatingWebhookServicePorts, tc.validatingWebhookConfigFiles,
			tc.validatingWebhookConfigNames, tc.validatingWebhookServiceNames, tc.validatingWebhookServicePorts)
		if wc != nil && wc.K8sCaCertWatcher != nil {
			defer wc.K8sCaCertWatcher.Close()
		}
		if wc != nil && wc.MutatingWebhookFileWatcher != nil {
			defer wc.MutatingWebhookFileWatcher.Close()
		}
		if wc != nil && wc.ValidatingWebhookFileWatcher != nil {
			defer wc.ValidatingWebhookFileWatcher.Close()
		}
		if err != nil {
			t.Errorf("failed to create a webhook controller: %v", err)
		}

		ret, found := wc.getServiceName(tc.scrtName)
		if tc.expectFound != found {
			t.Errorf("expected found (%v) differs from the actual found (%v)", tc.expectFound, found)
			continue
		}
		if found && tc.expectedSvcName != ret {
			t.Errorf("the service name (%v) returned is not as expcted (%v)", ret, tc.expectedSvcName)
		}
	}
}

func TestGetWebhookSecretNameFromSvcname(t *testing.T) {
	client := fake.NewSimpleClientset()
	mutatingWebhookConfigFiles := []string{"./test-data/empty-webhook-config.yaml"}
	validatingWebhookConfigFiles := []string{"./test-data/empty-webhook-config.yaml"}

	testCases := map[string]struct {
		deleteWebhookConfigOnExit     bool
		gracePeriodRatio              float32
		minGracePeriod                time.Duration
		k8sCaCertFile                 string
		namespace                     string
		mutatingWebhookConfigFiles    []string
		mutatingWebhookConfigNames    []string
		mutatingWebhookServiceNames   []string
		mutatingWebhookServicePorts   []int
		validatingWebhookConfigFiles  []string
		validatingWebhookConfigNames  []string
		validatingWebhookServiceNames []string
		validatingWebhookServicePorts []int
		svcName                       string
		expectedScrtName              string
	}{
		"expected secret name matches the return": {
			gracePeriodRatio:             0.6,
			k8sCaCertFile:                "./test-data/example-ca-cert.pem",
			mutatingWebhookConfigFiles:   mutatingWebhookConfigFiles,
			validatingWebhookConfigFiles: validatingWebhookConfigFiles,
			svcName:                      "foo",
			expectedScrtName:             "istio.webhook.foo",
		},
	}

	for _, tc := range testCases {
		wc, err := NewWebhookController(tc.deleteWebhookConfigOnExit, tc.gracePeriodRatio, tc.minGracePeriod,
			client.CoreV1(), client.AdmissionregistrationV1beta1(), client.CertificatesV1beta1(),
			tc.k8sCaCertFile, tc.namespace, tc.mutatingWebhookConfigFiles, tc.mutatingWebhookConfigNames,
			tc.mutatingWebhookServiceNames, tc.mutatingWebhookServicePorts, tc.validatingWebhookConfigFiles,
			tc.validatingWebhookConfigNames, tc.validatingWebhookServiceNames, tc.validatingWebhookServicePorts)
		if wc != nil && wc.K8sCaCertWatcher != nil {
			defer wc.K8sCaCertWatcher.Close()
		}
		if wc != nil && wc.MutatingWebhookFileWatcher != nil {
			defer wc.MutatingWebhookFileWatcher.Close()
		}
		if wc != nil && wc.ValidatingWebhookFileWatcher != nil {
			defer wc.ValidatingWebhookFileWatcher.Close()
		}
		if err != nil {
			t.Errorf("failed to create a webhook controller: %v", err)
		}

		ret := wc.getWebhookSecretNameFromSvcname(tc.svcName)
		if tc.expectedScrtName != ret {
			t.Errorf("the secret name (%v) returned is not as expcted (%v)", ret, tc.expectedScrtName)
		}
	}
}
