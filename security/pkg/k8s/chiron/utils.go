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
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"net"
	"reflect"
	"time"

	"k8s.io/api/admissionregistration/v1beta1"

	"github.com/ghodss/yaml"

	"istio.io/istio/pkg/spiffe"

	"istio.io/istio/security/pkg/pki/util"
	"istio.io/pkg/log"

	cert "k8s.io/api/certificates/v1beta1"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	admissionreg "k8s.io/client-go/kubernetes/typed/admissionregistration/v1beta1"
)

// Generate a certificate and key from k8s CA
// Working flow:
// 1. Generate a CSR
// 2. Submit a CSR
// 3. Approve a CSR
// 4. Read the signed certificate
// 5. Clean up the artifacts (e.g., delete CSR)
func genKeyCertK8sCA(wc *WebhookController, secretName string, secretNamespace, svcName string) ([]byte, []byte, error) {
	// 1. Generate a CSR
	// Construct the dns id from service name and name space.
	// Example: istio-pilot.istio-system.svc, istio-pilot.istio-system
	id := fmt.Sprintf("%s.%s.svc", svcName, secretNamespace)
	id += "," + fmt.Sprintf("%s.%s", svcName, secretNamespace)
	options := util.CertOptions{
		Host:       id,
		RSAKeySize: keySize,
		IsDualUse:  false,
		PKCS8Key:   false,
	}
	csrPEM, keyPEM, err := util.GenCSR(options)
	if err != nil {
		log.Errorf("CSR generation error (%v)", err)
		return nil, nil, err
	}

	// 2. Submit a CSR
	csrName := fmt.Sprintf("domain-%s-ns-%s-secret-%s", spiffe.GetTrustDomain(), secretNamespace, secretName)
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
	r, err := wc.certClient.CertificateSigningRequests().Create(k8sCSR)
	if err != nil {
		if !kerrors.IsAlreadyExists(err) {
			log.Debugf("failed to create CSR (%v): %v", csrName, err)
			return nil, nil, err
		}
		//Otherwise, delete the existing CSR and create again
		log.Debugf("delete an existing CSR: %v", csrName)
		err = wc.certClient.CertificateSigningRequests().Delete(csrName, nil)
		if err != nil {
			log.Errorf("failed to delete CSR (%v): %v", csrName, err)
			return nil, nil, err
		}
		log.Debugf("create CSR (%v) after the existing one was deleted", csrName)
		r, err = wc.certClient.CertificateSigningRequests().Create(k8sCSR)
		if err != nil {
			log.Debugf("failed to create CSR (%v): %v", csrName, err)
			return nil, nil, err
		}
	}
	log.Debugf("CSR (%v) is created: %v", csrName, r)

	// 3. Approve a CSR
	log.Debugf("approve CSR (%v) ...", csrName)
	r.Status.Conditions = append(r.Status.Conditions, cert.CertificateSigningRequestCondition{
		Type:    cert.CertificateApproved,
		Reason:  "k8s CSR is approved",
		Message: "The CSR is approved",
	})
	reqApproval, err := wc.certClient.CertificateSigningRequests().UpdateApproval(r)
	if err != nil {
		log.Debugf("failed to approve CSR (%v): %v", csrName, err)
		errCsr := wc.cleanUpCertGen(csrName)
		if errCsr != nil {
			log.Errorf("failed to clean up CSR (%v): %v", csrName, err)
		}
		return nil, nil, err
	}
	log.Debugf("CSR (%v) is approved: %v", csrName, reqApproval)

	// 4. Read the signed certificate
	var reqSigned *cert.CertificateSigningRequest
	for i := 0; i < maxNumCertRead; i++ {
		time.Sleep(certReadInterval)
		reqSigned, err = wc.certClient.CertificateSigningRequests().Get(csrName, metav1.GetOptions{})
		if err != nil {
			log.Errorf("failed to get the CSR (%v): %v", csrName, err)
			errCsr := wc.cleanUpCertGen(csrName)
			if errCsr != nil {
				log.Errorf("failed to clean up CSR (%v): %v", csrName, err)
			}
			return nil, nil, err
		}
		if reqSigned.Status.Certificate != nil {
			// Certificate is ready
			break
		}
	}
	var certPEM []byte
	if reqSigned.Status.Certificate != nil {
		log.Debugf("the length of the certificate is %v", len(reqSigned.Status.Certificate))
		log.Debugf("the certificate for CSR (%v) is: %v", csrName, string(reqSigned.Status.Certificate))
		certPEM = reqSigned.Status.Certificate
	} else {
		log.Errorf("failed to read the certificate for CSR (%v)", csrName)
		// Output the first CertificateDenied condition, if any, in the status
		for _, c := range r.Status.Conditions {
			if c.Type == cert.CertificateDenied {
				log.Errorf("CertificateDenied, name: %v, uid: %v, cond-type: %v, cond: %s",
					r.Name, r.UID, c.Type, c.String())
				break
			}
		}
		errCsr := wc.cleanUpCertGen(csrName)
		if errCsr != nil {
			log.Errorf("failed to clean up CSR (%v): %v", csrName, err)
		}
		return nil, nil, fmt.Errorf("failed to read the certificate for CSR (%v)", csrName)
	}
	caCert, err := wc.getCACert()
	if err != nil {
		log.Errorf("error when getting CA cert (%v)", err)
		return nil, nil, err
	}
	// Verify the certificate chain before returning the certificate
	roots := x509.NewCertPool()
	if roots == nil {
		errCsr := wc.cleanUpCertGen(csrName)
		if errCsr != nil {
			log.Errorf("failed to clean up CSR (%v): %v", csrName, err)
		}
		return nil, nil, fmt.Errorf("failed to create cert pool")
	}
	if ok := roots.AppendCertsFromPEM(caCert); !ok {
		errCsr := wc.cleanUpCertGen(csrName)
		if errCsr != nil {
			log.Errorf("failed to clean up CSR (%v): %v", csrName, err)
		}
		return nil, nil, fmt.Errorf("failed to append CA certificate")
	}
	certParsed, err := util.ParsePemEncodedCertificate(certPEM)
	if err != nil {
		log.Errorf("failed to parse the certificate: %v", err)
		errCsr := wc.cleanUpCertGen(csrName)
		if errCsr != nil {
			log.Errorf("failed to clean up CSR (%v): %v", csrName, err)
		}
		return nil, nil, fmt.Errorf("failed to parse the certificate: %v", err)
	}
	_, err = certParsed.Verify(x509.VerifyOptions{
		Roots: roots,
	})
	if err != nil {
		log.Errorf("failed to verify the certificate chain: %v", err)
		errCsr := wc.cleanUpCertGen(csrName)
		if errCsr != nil {
			log.Errorf("failed to clean up CSR (%v): %v", csrName, err)
		}
		return nil, nil, fmt.Errorf("failed to verify the certificate chain: %v", err)
	}
	certChain := []byte{}
	certChain = append(certChain, certPEM...)
	certChain = append(certChain, caCert...)

	// 5. Clean up the artifacts (e.g., delete CSR)
	err = wc.cleanUpCertGen(csrName)
	if err != nil {
		log.Errorf("failed to clean up CSR (%v): %v", csrName, err)
	}
	// If there is a failure of cleaning up CSR, the error is returned.
	return certChain, keyPEM, err
}

// Read CA certificate and check whether it is a valid certificate.
func readCACert(caCertPath string) ([]byte, error) {
	caCert, err := ioutil.ReadFile(caCertPath)
	if err != nil {
		log.Errorf("failed to read CA cert, cert. path: %v, error: %v", caCertPath, err)
		return nil, fmt.Errorf("failed to read CA cert, cert. path: %v, error: %v", caCertPath, err)
	}

	b, _ := pem.Decode(caCert)
	if b == nil {
		return nil, fmt.Errorf("could not decode pem")
	}
	if b.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("ca certificate contains wrong type: %v", b.Type)
	}
	if _, err := x509.ParseCertificate(b.Bytes); err != nil {
		return nil, fmt.Errorf("ca certificate parsing returns an error: %v", err)
	}

	return caCert, nil
}

func isTCPReachable(host string, port int) bool {
	addr := fmt.Sprintf("%s:%d", host, port)
	conn, err := net.DialTimeout("tcp", addr, 1*time.Second)
	if err != nil {
		log.Debugf("DialTimeout() returns err: %v", err)
		// No connection yet, so no need to conn.Close()
		return false
	}
	defer conn.Close()
	return true
}

// Rebuild the desired mutatingwebhookconfiguration from the specified CA
// and webhook config files.
func rebuildMutatingWebhookConfigHelper(
	caCert []byte, webhookConfigFile, webhookConfigName string,
) (*v1beta1.MutatingWebhookConfiguration, error) {
	log.Debugf("*********** enter rebuildMutatingWebhookConfigHelper()")
	// load and validate configuration
	webhookConfigData, err := ioutil.ReadFile(webhookConfigFile)
	if err != nil {
		return nil, err
	}
	var webhookConfig v1beta1.MutatingWebhookConfiguration
	if err := yaml.Unmarshal(webhookConfigData, &webhookConfig); err != nil {
		return nil, fmt.Errorf("could not decode mutatingwebhookconfiguration from %v: %v",
			webhookConfigFile, err)
	}

	// the webhook name is fixed at startup time
	webhookConfig.Name = webhookConfigName

	// patch the ca-cert into the user provided configuration
	for i := range webhookConfig.Webhooks {
		webhookConfig.Webhooks[i].ClientConfig.CABundle = caCert
	}

	return &webhookConfig, nil
}

// Rebuild the desired validatingwebhookconfiguration from the specified CA
// and webhook config files.
func rebuildValidatingWebhookConfigHelper(
	caCert []byte, webhookConfigFile, webhookConfigName string,
) (*v1beta1.ValidatingWebhookConfiguration, error) {
	log.Debugf("*********** enter rebuildValidatingWebhookConfigHelper()")
	// load and validate configuration
	webhookConfigData, err := ioutil.ReadFile(webhookConfigFile)
	if err != nil {
		return nil, err
	}
	var webhookConfig v1beta1.ValidatingWebhookConfiguration
	if err := yaml.Unmarshal(webhookConfigData, &webhookConfig); err != nil {
		return nil, fmt.Errorf("could not decode validatingwebhookconfiguration from %v: %v",
			webhookConfigFile, err)
	}

	// the webhook name is fixed at startup time
	webhookConfig.Name = webhookConfigName

	// patch the ca-cert into the user provided configuration
	for i := range webhookConfig.Webhooks {
		webhookConfig.Webhooks[i].ClientConfig.CABundle = caCert
	}

	return &webhookConfig, nil
}

// Create the specified mutatingwebhookconfiguration resource or, if the resource
// already exists, update it's contents with the desired state.
func createOrUpdateMutatingWebhookConfigHelper(
	client admissionreg.MutatingWebhookConfigurationInterface,
	webhookConfig *v1beta1.MutatingWebhookConfiguration,
) (bool, error) {
	log.Debugf("*********** enter createOrUpdateMutatingWebhookConfigHelper()")

	current, err := client.Get(webhookConfig.Name, metav1.GetOptions{})
	if err != nil {
		log.Debugf("*********** get webhookConfig %v returns an err: %v", webhookConfig.Name, err)
		// If the mutatingwebhookconfiguration does not exist yet, create the config.
		if kerrors.IsNotFound(err) {
			log.Debugf("*********** get webhookConfig %v err is NotFound", webhookConfig.Name)
			// Create the mutatingwebhookconfiguration
			if _, createErr := client.Create(webhookConfig); createErr != nil {
				return false, createErr
			}
			return true, nil
		}
		log.Debugf("*********** get webhookConfig %v err is NOT NotFound", webhookConfig.Name)
		// There is an error when getting the webhookconfiguration and the error is
		// not that the webhookconfiguration does not exist. In this case, simply
		// return and skip the update.
		return false, err
	}
	// Otherwise, when getting the webhookconfiguration returns nil, update the configuration
	// only if the webhooks in the current is different from those configured. Only copy the relevant fields
	// that we want reconciled and ignore everything else, e.g. labels, selectors.
	updated := current.DeepCopyObject().(*v1beta1.MutatingWebhookConfiguration)
	updated.Webhooks = webhookConfig.Webhooks
	log.Debugf("*********** after assignment, updated.Webhooks is %v", updated.Webhooks)

	if !reflect.DeepEqual(updated, current) {
		log.Debugf("*********** reflect.DeepEqual(updated, current) returns false")
		// Update mutatingwebhookconfiguration to based on current and the webhook configured.
		_, err := client.Update(updated)
		if err != nil {
			log.Errorf("update webhookconfiguration returns err: %v", err)
		}
		return true, err
	}
	log.Debugf("*********** return false, nil error")
	return false, nil
}

// Create the specified validatingwebhookconfiguration resource or, if the resource
// already exists, update it's contents with the desired state.
func createOrUpdateValidatingWebhookConfigHelper(
	client admissionreg.ValidatingWebhookConfigurationInterface,
	webhookConfig *v1beta1.ValidatingWebhookConfiguration,
) (bool, error) {
	log.Debugf("*********** enter createOrUpdateValidatingWebhookConfigHelper()")

	current, err := client.Get(webhookConfig.Name, metav1.GetOptions{})
	if err != nil {
		log.Debugf("*********** get webhookConfig %v returns an err: %v", webhookConfig.Name, err)
		// If the validatingwebhookconfiguration does not exist yet, create the config.
		if kerrors.IsNotFound(err) {
			log.Debugf("*********** get webhookConfig %v err is NotFound", webhookConfig.Name)
			// Create the validatingwebhookconfiguration
			if _, createErr := client.Create(webhookConfig); createErr != nil {
				return false, createErr
			}
			return true, nil
		}
		log.Debugf("*********** get webhookConfig %v err is NOT NotFound", webhookConfig.Name)
		// There is an error when getting the webhookconfiguration and the error is
		// not that the webhookconfiguration does not exist. In this case, simply
		// return and skip the update.
		return false, err
	}
	// Otherwise, when getting the webhookconfiguration returns nil, update the configuration
	// only if the webhooks in the current is different from those configured. Only copy the relevant fields
	// that we want reconciled and ignore everything else, e.g. labels, selectors.
	updated := current.DeepCopyObject().(*v1beta1.ValidatingWebhookConfiguration)
	updated.Webhooks = webhookConfig.Webhooks
	log.Debugf("*********** after assignment, updated.Webhooks is %v", updated.Webhooks)

	if !reflect.DeepEqual(updated, current) {
		log.Debugf("*********** reflect.DeepEqual(updated, current) returns false")
		// Update validatingwebhookconfiguration to based on current and the webhook configured.
		_, err := client.Update(updated)
		if err != nil {
			log.Errorf("update webhookconfiguration returns err: %v", err)
		}
		return true, err
	}
	log.Debugf("*********** return false, nil error")
	return false, nil
}

// Update the mutatingwebhookconfiguration
func updateMutatingWebhookConfig(wc *WebhookController) {
	certChanged, err := reloadCaCert(wc)
	if err == nil && certChanged {
		updateCertAndWebhookConfig(wc)
		return
	}

	// Rebuild the webhook configuration and reconcile with the
	// existing mutatingwebhookconfiguration.
	if err := wc.rebuildMutatingWebhookConfig(); err == nil {
		updateErr := wc.createOrUpdateMutatingWebhookConfig()
		if updateErr != nil {
			log.Errorf("error when updating mutatingwebhookconfiguration: %v", updateErr)
		}
	}
}

// Update the validatingwebhookconfiguration
func updateValidatingWebhookConfig(wc *WebhookController) {
	certChanged, err := reloadCaCert(wc)
	if err == nil && certChanged {
		updateCertAndWebhookConfig(wc)
		return
	}

	// Rebuild the webhook configuration and reconcile with the
	// existing validatingwebhookconfiguration.
	if err := wc.rebuildValidatingWebhookConfig(); err == nil {
		updateErr := wc.createOrUpdateValidatingWebhookConfig()
		if updateErr != nil {
			log.Errorf("error when updating validatingwebhookconfiguration: %v", updateErr)
		}
	}
}

// Update the CA certificate and webhookconfiguration
func updateCertAndWebhookConfig(wc *WebhookController) {
	certChanged, err := reloadCaCert(wc)
	if err != nil || !certChanged {
		// No certificate change
		return
	}
	log.Debug("CA cert changed, update webhook certs and webhook configuration")
	// Update the webhook certificates
	for _, name := range WebhookServiceNames {
		wc.upsertSecret(wc.getWebhookSecretNameFromSvcname(name), wc.namespace)
	}

	// Rebuild the webhook configuration and reconcile with the
	// existing mutatingwebhookconfiguration.
	if err := wc.rebuildMutatingWebhookConfig(); err == nil {
		updateErr := wc.createOrUpdateMutatingWebhookConfig()
		if updateErr != nil {
			log.Errorf("error when updating mutatingwebhookconfiguration: %v", updateErr)
		}
	}
}

// Reload CA cert from file and return whether CA cert is changed
func reloadCaCert(wc *WebhookController) (bool, error) {
	certChanged := false
	wc.mutex.Lock()
	defer wc.mutex.Unlock()
	caCert, err := readCACert(wc.k8sCaCertFile)
	if err != nil {
		return certChanged, err
	}
	if !bytes.Equal(caCert, wc.CACert) {
		wc.CACert = append([]byte(nil), caCert...)
		certChanged = true
	}
	return certChanged, nil
}
