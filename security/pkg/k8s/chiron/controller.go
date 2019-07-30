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
	"path/filepath"
	"sync"
	"time"

	"k8s.io/api/admissionregistration/v1beta1"
	"k8s.io/client-go/kubernetes"

	"github.com/ghodss/yaml"
	"github.com/howeyc/fsnotify"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"

	certclient "k8s.io/client-go/kubernetes/typed/certificates/v1beta1"
	corev1 "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/tools/cache"

	"istio.io/istio/security/pkg/listwatch"
	"istio.io/istio/security/pkg/pki/ca"
	"istio.io/istio/security/pkg/pki/util"
	"istio.io/pkg/log"
)

type WebhookType int

const (
	MutatingWebhook WebhookType = iota
	ValidatingWebhook
)

/* #nosec: disable gas linter */
const (
	// The prefix of webhook secret name
	prefixWebhookSecretName = "istio.webhook"

	// The Istio webhook secret annotation type
	IstioSecretType = "istio.io/webhook-key-and-cert"

	// The ID/name for the certificate chain file.
	CertChainID = "cert-chain.pem"
	// The ID/name for the private key file.
	PrivateKeyID = "key.pem"
	// The ID/name for the CA root certificate file.
	RootCertID = "root-cert.pem"

	// For debugging, set the resync period to be a shorter period.
	secretResyncPeriod = 10 * time.Second
	// secretResyncPeriod = time.Minute

	recommendedMinGracePeriodRatio = 0.2
	recommendedMaxGracePeriodRatio = 0.8

	// The size of a private key for a leaf certificate.
	keySize = 2048

	// The number of retries when requesting to create secret.
	secretCreationRetry = 3

	// The interval for reading a certificate
	certReadInterval = 500 * time.Millisecond
	// The number of tries for reading a certificate
	maxNumCertRead = 20

	// The delay introduced to debounce the CA cert events
	watchDebounceDelay = 100 * time.Millisecond
)

var (
	// TODO (lei-tang): the secret names, service names, ports may be moved to CLI.

	// WebhookServiceNames is service names of the webhooks.
	WebhookServiceNames = []string{
		// "protomutate",
		// "protovalidate",
		"istio-sidecar-injector",
		"istio-galley",
	}

	// WebhookTypes is the types of the webhooks. Each item corresponds to an item
	//at the same index in WebhookServiceNames.
	WebhookTypes = []WebhookType{
		MutatingWebhook,
		ValidatingWebhook,
	}

	// WebhookServicePorts is service ports of the webhooks. Each item corresponds to an item
	// at the same index in WebhookServiceNames.
	WebhookServicePorts = []int{
		443,
		443,
	}
)

// WebhookController manages the service accounts' secrets that contains Istio keys and certificates.
type WebhookController struct {
	k8sClient      *kubernetes.Clientset
	core           corev1.CoreV1Interface
	minGracePeriod time.Duration
	// Length of the grace period for the certificate rotation.
	gracePeriodRatio float32

	// Controller and store for secret objects.
	scrtController cache.Controller
	scrtStore      cache.Store

	certClient certclient.CertificatesV1beta1Interface

	// The file path to the k8s CA certificate
	k8sCaCertFile string

	// The namespace of the webhook certificates
	namespace string

	// The file paths of MutatingWebhookConfiguration
	mutatingWebhookConfigFiles []string
	// The names of MutatingWebhookConfiguration
	mutatingWebhookConfigNames []string
	// The configuration of mutating webhook
	mutatingWebhookConfig *v1beta1.MutatingWebhookConfiguration

	// The file paths of ValidatingWebhookConfiguration
	validatingWebhookConfigFiles []string
	// The names of ValidatingWebhookConfiguration
	validatingWebhookConfigNames []string
	// The configuration of validating webhook
	validatingWebhookConfig *v1beta1.ValidatingWebhookConfiguration

	// Watcher for the k8s CA cert file
	K8sCaCertWatcher *fsnotify.Watcher
	// Watcher for the mutatingwebhook config file
	MutatingWebhookFileWatcher *fsnotify.Watcher
	// Watcher for the validatingwebhook config file
	ValidatingWebhookFileWatcher *fsnotify.Watcher

	// Current CA certificate
	CACert []byte

	mutex sync.RWMutex
}

// NewWebhookController returns a pointer to a newly constructed WebhookController instance.
func NewWebhookController(gracePeriodRatio float32, minGracePeriod time.Duration, k8sClient *kubernetes.Clientset,
	k8sCaCertFile, nameSpace string, mutatingWebhookConfigFiles, mutatingWebhookConfigNames,
	validatingWebhookConfigFiles, validatingWebhookConfigNames []string) (*WebhookController, error) {

	if gracePeriodRatio < 0 || gracePeriodRatio > 1 {
		return nil, fmt.Errorf("grace period ratio %f should be within [0, 1]", gracePeriodRatio)
	}
	if gracePeriodRatio < recommendedMinGracePeriodRatio || gracePeriodRatio > recommendedMaxGracePeriodRatio {
		log.Warnf("grace period ratio %f is out of the recommended window [%.2f, %.2f]",
			gracePeriodRatio, recommendedMinGracePeriodRatio, recommendedMaxGracePeriodRatio)
	}

	core := k8sClient.CoreV1()
	c := &WebhookController{
		gracePeriodRatio:             gracePeriodRatio,
		minGracePeriod:               minGracePeriod,
		k8sCaCertFile:                k8sCaCertFile,
		k8sClient:                    k8sClient,
		core:                         core,
		certClient:                   k8sClient.CertificatesV1beta1(),
		namespace:                    nameSpace,
		mutatingWebhookConfigFiles:   mutatingWebhookConfigFiles,
		mutatingWebhookConfigNames:   mutatingWebhookConfigNames,
		validatingWebhookConfigFiles: validatingWebhookConfigFiles,
		validatingWebhookConfigNames: validatingWebhookConfigNames,
	}

	// read CA cert at the beginning of launching the controller and when the CA cert changes.
	caCert, err := readCACert(k8sCaCertFile)
	if err != nil {
		log.Errorf("failed to read CA certificate: %v", err)
		return nil, err
	}
	c.setCACert(caCert)

	namespaces := []string{nameSpace}

	istioSecretSelector := fields.SelectorFromSet(map[string]string{"type": IstioSecretType}).String()
	scrtLW := listwatch.MultiNamespaceListerWatcher(namespaces, func(namespace string) cache.ListerWatcher {
		return &cache.ListWatch{
			ListFunc: func(options metav1.ListOptions) (runtime.Object, error) {
				options.FieldSelector = istioSecretSelector
				return core.Secrets(namespace).List(options)
			},
			WatchFunc: func(options metav1.ListOptions) (watch.Interface, error) {
				options.FieldSelector = istioSecretSelector
				return core.Secrets(namespace).Watch(options)
			},
		}
	})
	// The certificate rotation is handled by scrtUpdated().
	c.scrtStore, c.scrtController =
		cache.NewInformer(scrtLW, &v1.Secret{}, secretResyncPeriod, cache.ResourceEventHandlerFuncs{
			DeleteFunc: c.scrtDeleted,
			UpdateFunc: c.scrtUpdated,
		})

	watchers := []**fsnotify.Watcher{&c.K8sCaCertWatcher, &c.MutatingWebhookFileWatcher, &c.ValidatingWebhookFileWatcher}
	// Create a watcher such that when the file changes, the event is detected.
	// Each watcher corresponds to a file.
	// Watch the parent directory of the target files so we can catch
	// symlink updates of k8s ConfigMaps volumes.
	// The files watched include the CA certificate file and the webhookconfiguration files,
	// which are ConfigMap file mounts.
	// In the prototype, only the first webhookconfiguration is watched.
	files := []string{k8sCaCertFile, mutatingWebhookConfigFiles[0], validatingWebhookConfigFiles[0]}
	for i, _ := range watchers {
		*watchers[i], err = fsnotify.NewWatcher()
		if err != nil {
			return nil, err
		}
		watchDir, _ := filepath.Split(files[i])
		if err := (*watchers[i]).Watch(watchDir); err != nil {
			return nil, fmt.Errorf("could not watch %v: %v", files[i], err)
		}
	}
	log.Debugf("*************** K8sCaCertWatcher is %v", c.K8sCaCertWatcher)
	log.Debugf("*************** MutatingWebhookFileWatcher is %v", c.MutatingWebhookFileWatcher)
	log.Debugf("*************** ValidatingWebhookFileWatcher is %v", c.ValidatingWebhookFileWatcher)

	return c, nil
}

// Run starts the WebhookController until stopCh is notified.
func (wc *WebhookController) Run(stopCh chan struct{}) {
	log.Debugf("*************** enter Run() of WebhookController")

	// Create secrets containing certificates for webhooks
	for _, svcName := range WebhookServiceNames {
		wc.upsertSecret(wc.getWebhookSecretNameFromSvcname(svcName), wc.namespace)
	}

	// Currently, Chiron only patches one mutating webhook and one validating webhook.
	idxMutate := wc.getMutatingWebhookItemIdx()
	var mutatingWebhookChangedCh chan struct{}
	if idxMutate < 0 {
		log.Warn("no mutatingwebhook item is found")
	} else {
		hostMutate := fmt.Sprintf("%s.%s", WebhookServiceNames[idxMutate], wc.namespace)
		go wc.checkAndCreateMutatingWebhook(hostMutate, WebhookServicePorts[idxMutate], stopCh)
		// Only the first mutatingWebhookConfigNames is supported
		mutatingWebhookChangedCh = wc.monitorMutatingWebhookConfig(wc.mutatingWebhookConfigNames[0], stopCh)
	}

	idxValidate := wc.getValidatingWebhookItemIdx()
	var validatingWebhookChangedCh chan struct{}
	if idxValidate < 0 {
		log.Warn("no validatingwebhook item is found")
	} else {
		hostValidate := fmt.Sprintf("%s.%s", WebhookServiceNames[idxValidate], wc.namespace)
		go wc.checkAndCreateValidatingWebhook(hostValidate, WebhookServicePorts[idxValidate], stopCh)
		// Only the first validatingWebhookConfigNames is supported
		validatingWebhookChangedCh = wc.monitorValidatingWebhookConfig(wc.validatingWebhookConfigNames[0], stopCh)
	}

	// Manage the secrets of webhooks
	go wc.scrtController.Run(stopCh)

	// upsertSecret to update and insert secret
	// it throws error if the secret cache is not synchronized, but the secret exists in the system
	cache.WaitForCacheSync(stopCh, wc.scrtController.HasSynced)

	// Watch for the CA certificate and webhookconfiguration updates
	go wc.watchConfigChanges(mutatingWebhookChangedCh, validatingWebhookChangedCh, stopCh)
}

func (wc *WebhookController) upsertSecret(secretName, secretNamespace string) {
	secret := ca.BuildSecretFromSecretName(secretName, secretNamespace, nil, nil, nil, nil, nil, IstioSecretType)

	log.Debugf("********** upsertSecret() searches for the secret (%v) to insert", secret)
	existingSecret, err := wc.core.Secrets(secretNamespace).Get(secretName, metav1.GetOptions{})
	if err == nil && existingSecret != nil {
		log.Debugf("********** upsertSecret(): the secret (%v) in namespace (%v) exists, return",
			secretName, secretNamespace)
		// Do nothing for existing secrets. Rotating expiring certs are handled by the `scrtUpdated` method.
		return
	}

	log.Debugf("********** upsertSecret(): the secret (%v) in namespace (%v) does not exist, creat it.",
		secretName, secretNamespace)

	svcName, found := wc.getServiceName(secretName)
	if !found {
		log.Errorf("failed to find the service name for the secret (%v) to insert", secretName)
		return
	}

	// Now we know the secret does not exist yet. So we create a new one.
	chain, key, err := genKeyCertK8sCA(wc, secretName, secretNamespace, svcName)
	if err != nil {
		log.Errorf("failed to generate key and certificate for secret %v in namespace %v (error %v)",
			secretName, secretNamespace, err)
		return
	}
	cert, err := wc.getCACert()
	if err != nil {
		log.Errorf("failed to get CA certificate: %v", err)
		return
	}
	secret.Data = map[string][]byte{
		CertChainID:  chain,
		PrivateKeyID: key,
		RootCertID:   cert,
	}

	// We retry several times when create secret to mitigate transient network failures.
	for i := 0; i < secretCreationRetry; i++ {
		_, err = wc.core.Secrets(secretNamespace).Create(secret)
		if err == nil || errors.IsAlreadyExists(err) {
			if errors.IsAlreadyExists(err) {
				log.Infof("Istio secret \"%s\" in namespace \"%s\" already exists", secretName, secretNamespace)
			}
			break
		} else {
			log.Errorf("Failed to create secret in attempt %v/%v, (error: %s)", i+1, secretCreationRetry, err)
		}
		time.Sleep(time.Second)
	}

	if err != nil && !errors.IsAlreadyExists(err) {
		log.Errorf("Failed to create secret \"%s\" in namespace \"%s\" (error: %s), retries %v times",
			secretName, secretNamespace, err, secretCreationRetry)
		return
	}

	log.Infof("Istio secret \"%s\" in namespace \"%s\" has been created", secretName, secretNamespace)
}

func (wc *WebhookController) scrtDeleted(obj interface{}) {
	log.Debugf("*************** enter scrtDeleted()")
	scrt, ok := obj.(*v1.Secret)
	if !ok {
		log.Warnf("Failed to convert to secret object: %v", obj)
		return
	}

	scrtName := scrt.Name
	if wc.isWebhookSecret(scrtName, scrt.GetNamespace()) {
		log.Errorf("Re-create deleted Istio secret for existing secret %s in namespace %s", scrtName, scrt.GetNamespace())
		wc.upsertSecret(scrtName, scrt.GetNamespace())
	}
}

// scrtUpdated() is the callback function for update event. It handles
// the certificate rotations.
func (wc *WebhookController) scrtUpdated(oldObj, newObj interface{}) {
	log.Debugf("*************** enter scrtUpdated()")
	scrt, ok := newObj.(*v1.Secret)
	if !ok {
		log.Warnf("Failed to convert to secret object: %v", newObj)
		return
	}
	namespace := scrt.GetNamespace()
	name := scrt.GetName()
	// Only handle webhook secret update events
	if !wc.isWebhookSecret(name, namespace) {
		log.Debugf("*************** not a webhook secret, return")
		return
	}

	certBytes := scrt.Data[CertChainID]
	cert, err := util.ParsePemEncodedCertificate(certBytes)
	if err != nil {
		log.Warnf("Failed to parse certificates in secret %s/%s (error: %v), refreshing the secret.",
			namespace, name, err)
		if err = wc.refreshSecret(scrt); err != nil {
			log.Errora(err)
		}

		return
	}

	certLifeTimeLeft := time.Until(cert.NotAfter)
	certLifeTime := cert.NotAfter.Sub(cert.NotBefore)
	// TODO(myidpt): we may introduce a minimum gracePeriod, without making the config too complex.
	// Because time.Duration only takes int type, multiply gracePeriodRatio by 1000 and then divide it.
	gracePeriod := time.Duration(wc.gracePeriodRatio*1000) * certLifeTime / 1000
	if gracePeriod < wc.minGracePeriod {
		log.Warnf("gracePeriod (%v * %f) = %v is less than minGracePeriod %v. Apply minGracePeriod.",
			certLifeTime, wc.gracePeriodRatio, gracePeriod, wc.minGracePeriod)
		gracePeriod = wc.minGracePeriod
	}

	// Refresh the secret if 1) the certificate contained in the secret is about
	// to expire, or 2) the root certificate in the secret is different than the
	// one held by the ca (this may happen when the CA is restarted and
	// a new self-signed CA cert is generated).
	caCert, err := wc.getCACert()
	if err != nil {
		log.Errorf("failed to get CA certificate: %v", err)
		return
	}
	if certLifeTimeLeft < gracePeriod || !bytes.Equal(caCert, scrt.Data[RootCertID]) {
		log.Infof("Refreshing secret %s/%s, either the leaf certificate is about to expire "+
			"or the root certificate is outdated", namespace, name)

		if err = wc.refreshSecret(scrt); err != nil {
			log.Errorf("Failed to update secret %s/%s (error: %s)", namespace, name, err)
		}
	}
}

// refreshSecret is an inner func to refresh cert secrets when necessary
func (wc *WebhookController) refreshSecret(scrt *v1.Secret) error {
	namespace := scrt.GetNamespace()
	scrtName := scrt.Name

	svcName, found := wc.getServiceName(scrtName)
	if !found {
		return fmt.Errorf("failed to find the service name for the secret (%v) to refresh", scrtName)
	}

	chain, key, err := genKeyCertK8sCA(wc, scrtName, namespace, svcName)
	if err != nil {
		return err
	}

	caCert, err := wc.getCACert()
	if err != nil {
		return err
	}
	scrt.Data[CertChainID] = chain
	scrt.Data[PrivateKeyID] = key
	scrt.Data[RootCertID] = caCert

	_, err = wc.core.Secrets(namespace).Update(scrt)
	return err
}

// Clean up the CSR
func (wc *WebhookController) cleanUpCertGen(csrName string) error {
	// Delete CSR
	log.Debugf("delete CSR: %v", csrName)
	err := wc.certClient.CertificateSigningRequests().Delete(csrName, nil)
	if err != nil {
		log.Errorf("failed to delete CSR (%v): %v", csrName, err)
		return err
	}
	return nil
}

// Return whether the input secret name is a Webhook secret
func (wc *WebhookController) isWebhookSecret(name, namespace string) bool {
	for _, n := range WebhookServiceNames {
		if name == wc.getWebhookSecretNameFromSvcname(n) && namespace == wc.namespace {
			return true
		}
	}
	return false
}

func (wc *WebhookController) watchConfigChanges(mutatingWebhookChangedCh, validatingWebhookChangedCh,
	stopCh chan struct{}) {
	var timerCert <-chan time.Time
	var timerMutateWhFile <-chan time.Time
	var timerValidateWhFile <-chan time.Time

	for {
		select {
		// TODO (lei-tang): investigate whether some channels can be shared. The channels
		// are separated now so one channel will not affect another.
		case <-timerCert:
			log.Debugf("************* enter timerCert handler")
			timerCert = nil
			updateCertAndWebhookConfig(wc)
		case <-timerMutateWhFile:
			log.Debugf("************* enter timerMutateWhFile handler")
			timerMutateWhFile = nil
			updateMutatingWebhookConfig(wc)
		case <-timerValidateWhFile:
			log.Debugf("************* enter timerValidateWhFile handler")
			timerValidateWhFile = nil
			updateValidatingWebhookConfig(wc)
		case event := <-wc.K8sCaCertWatcher.Event:
			log.Debugf("*************** K8sCaCertWatcher.Event is triggered")
			// use a timer to debounce configuration updates
			if (event.IsModify() || event.IsCreate()) && timerCert == nil {
				timerCert = time.After(watchDebounceDelay)
			}
		case err := <-wc.K8sCaCertWatcher.Error:
			log.Errorf("******************* K8sCaCertWatcher error: %v", err)

		case event := <-wc.MutatingWebhookFileWatcher.Event:
			log.Debugf("*************** MutatingWebhookFileWatcher.Event is triggered")
			// use a timer to debounce configuration updates
			if (event.IsModify() || event.IsCreate()) && timerMutateWhFile == nil {
				timerMutateWhFile = time.After(watchDebounceDelay)
			}
		case err := <-wc.MutatingWebhookFileWatcher.Error:
			log.Errorf("******************* MutatingWebhookFileWatcher error: %v", err)

		case event := <-wc.ValidatingWebhookFileWatcher.Event:
			log.Debugf("*************** ValidatingWebhookFileWatcher.Event is triggered")
			// use a timer to debounce configuration updates
			if (event.IsModify() || event.IsCreate()) && timerValidateWhFile == nil {
				timerValidateWhFile = time.After(watchDebounceDelay)
			}
		case err := <-wc.ValidatingWebhookFileWatcher.Error:
			log.Errorf("******************* ValidatingWebhookFileWatcher error: %v", err)

		case <-mutatingWebhookChangedCh:
			log.Debugf("******************* mutatingwebhookconfiguration changes detected")
			// When mutatingwebhookconfiguration updates, create or update
			// mutatingwebhookconfiguration based on the config from rebuildMutatingWebhookConfig().
			updateErr := wc.createOrUpdateMutatingWebhookConfig()
			if updateErr != nil {
				log.Errorf("error when updating mutatingwebhookconfiguration: %v", updateErr)
			}
		case <-validatingWebhookChangedCh:
			log.Debugf("******************* validatingwebhookconfiguration changes detected")
			// When validatingwebhookconfiguration updates, create or update
			// validatingwebhookconfiguration based on the config from rebuildValidatingWebhookConfig().
			updateErr := wc.createOrUpdateValidatingWebhookConfig()
			if updateErr != nil {
				log.Errorf("error when updating validatingwebhookconfiguration: %v", updateErr)
			}

		case <-stopCh:
			return
		}
	}
}

func (wc *WebhookController) getCACert() ([]byte, error) {
	wc.mutex.Lock()
	cp := append([]byte(nil), wc.CACert...)
	wc.mutex.Unlock()

	block, _ := pem.Decode(cp)
	if block == nil {
		return nil, fmt.Errorf("invalid PEM encoded CA certificate")
	}
	if _, err := x509.ParseCertificate(block.Bytes); err != nil {
		return nil, fmt.Errorf("invalid ca certificate (%v), parsing error: %v", string(cp), err)
	}
	return cp, nil
}

func (wc *WebhookController) setCACert(cert []byte) {
	wc.mutex.Lock()
	wc.CACert = append([]byte(nil), cert...)
	wc.mutex.Unlock()
}

// Get the service name for the secret. Return the service name and whether it is found.
func (wc *WebhookController) getServiceName(secretName string) (string, bool) {
	for _, name := range WebhookServiceNames {
		if wc.getWebhookSecretNameFromSvcname(name) == secretName {
			return name, true
		}
	}
	return "", false
}

// Create or update the mutatingwebhookconfiguration based on the config from rebuildMutatingWebhookConfig().
func (wc *WebhookController) createOrUpdateMutatingWebhookConfig() error {
	log.Debugf("****************** enter createOrUpdateMutatingWebhookConfig()")
	if wc.mutatingWebhookConfig == nil {
		return fmt.Errorf("mutatingwebhookconfiguration is nil")
	}

	client := wc.k8sClient.AdmissionregistrationV1beta1().MutatingWebhookConfigurations()
	updated, err := createOrUpdateMutatingWebhookConfigHelper(client, wc.mutatingWebhookConfig)
	if err != nil {
		return err
	} else if updated {
		log.Infof("%v mutatingwebhookconfiguration updated", wc.mutatingWebhookConfig.Name)
	}
	return nil
}

// Create or update the validatingwebhookconfiguration based on the config from rebuildValidatingWebhookConfig().
func (wc *WebhookController) createOrUpdateValidatingWebhookConfig() error {
	log.Debugf("****************** enter createOrUpdateValidatingWebhookConfig()")
	if wc.validatingWebhookConfig == nil {
		return fmt.Errorf("validatingwebhookconfiguration is nil")
	}

	client := wc.k8sClient.AdmissionregistrationV1beta1().ValidatingWebhookConfigurations()
	updated, err := createOrUpdateValidatingWebhookConfigHelper(client, wc.validatingWebhookConfig)
	if err != nil {
		return err
	} else if updated {
		log.Infof("%v validatingwebhookconfiguration updated", wc.validatingWebhookConfig.Name)
	}
	return nil
}

func (wc *WebhookController) checkAndCreateMutatingWebhook(host string, port int, stopCh chan struct{}) {
	log.Debugf("****************** enter checkAndCreateMutatingWebhook()")

	// Check the webhook service status. Only configure webhook if the webhook service is available.
	for {
		if isTCPReachable(host, port) {
			log.Info("the webhook service is reachable")
			break
		}
		select {
		case <-stopCh:
			log.Debugf("webhook controlller is stopped")
			return
		default:
			log.Debugf("the webhook service at (%v, %v) is unreachable, check again later ...", host, port)
			time.Sleep(2 * time.Second)
		}
	}
	// Try to create the initial webhook configuration (if it doesn't already exist).
	err := wc.rebuildMutatingWebhookConfig()
	if err == nil {
		createErr := wc.createOrUpdateMutatingWebhookConfig()
		if createErr != nil {
			log.Errorf("error when creating or updating muatingwebhookconfiguration: %v", createErr)
			return
		} else {
			log.Errorf("error when rebuilding mutatingwebhookconfiguration: %v", err)
		}
	}
}

func (wc *WebhookController) checkAndCreateValidatingWebhook(host string, port int, stopCh chan struct{}) {
	log.Debugf("****************** enter checkAndCreateValidatingWebhook()")

	// Check the webhook service status. Only configure webhook if the webhook service is available.
	for {
		if isTCPReachable(host, port) {
			log.Info("the webhook service is reachable")
			break
		}
		select {
		case <-stopCh:
			log.Debugf("webhook controlller is stopped")
			return
		default:
			log.Debugf("the webhook service is unreachable, check again later ...")
			time.Sleep(2 * time.Second)
		}
	}
	// Try to create the initial webhook configuration (if it doesn't already exist).
	err := wc.rebuildValidatingWebhookConfig()
	if err == nil {
		createErr := wc.createOrUpdateValidatingWebhookConfig()
		if createErr != nil {
			log.Errorf("error when creating or updating validatingwebhookconfiguration: %v", createErr)
			return
		}
	} else {
		log.Errorf("error when rebuilding mutatingwebhookconfiguration: %v", err)
	}
}

// Run an informer that watches the changes of mutatingwebhookconfiguration.
func (wc *WebhookController) monitorMutatingWebhookConfig(webhookConfigName string, stopC <-chan struct{}) chan struct{} {
	webhookChangedCh := make(chan struct{}, 1000)

	watchlist := cache.NewListWatchFromClient(
		wc.k8sClient.AdmissionregistrationV1beta1().RESTClient(),
		"mutatingwebhookconfigurations",
		"",
		fields.ParseSelectorOrDie(fmt.Sprintf("metadata.name=%s", webhookConfigName)))

	_, controller := cache.NewInformer(
		watchlist,
		&v1beta1.MutatingWebhookConfiguration{},
		0,
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(_ interface{}) {
				log.Debugf("************ AddFunc() in monitorMutatingWebhookConfig()")
				webhookChangedCh <- struct{}{}
			},
			UpdateFunc: func(prev, curr interface{}) {
				log.Debugf("************ UpdateFunc() in monitorMutatingWebhookConfig()")
				prevObj := prev.(*v1beta1.MutatingWebhookConfiguration)
				currObj := curr.(*v1beta1.MutatingWebhookConfiguration)
				if prevObj.ResourceVersion != currObj.ResourceVersion {
					webhookChangedCh <- struct{}{}
				}
			},
			DeleteFunc: func(_ interface{}) {
				log.Debugf("************ DeleteFunc() in monitorMutatingWebhookConfig()")
				webhookChangedCh <- struct{}{}
			},
		},
	)
	go controller.Run(stopC)
	return webhookChangedCh
}

// Run an informer that watches the changes of validatingwebhookconfiguration.
func (wc *WebhookController) monitorValidatingWebhookConfig(webhookConfigName string, stopC <-chan struct{}) chan struct{} {
	webhookChangedCh := make(chan struct{}, 1000)

	watchlist := cache.NewListWatchFromClient(
		wc.k8sClient.AdmissionregistrationV1beta1().RESTClient(),
		"validatingwebhookconfigurations",
		"",
		fields.ParseSelectorOrDie(fmt.Sprintf("metadata.name=%s", webhookConfigName)))

	_, controller := cache.NewInformer(
		watchlist,
		&v1beta1.ValidatingWebhookConfiguration{},
		0,
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(_ interface{}) {
				log.Debugf("************ AddFunc() in monitorValidatingWebhookConfig()")
				webhookChangedCh <- struct{}{}
			},
			UpdateFunc: func(prev, curr interface{}) {
				log.Debugf("************ UpdateFunc() in monitorValidatingWebhookConfig()")
				prevObj := prev.(*v1beta1.ValidatingWebhookConfiguration)
				currObj := curr.(*v1beta1.ValidatingWebhookConfiguration)
				if prevObj.ResourceVersion != currObj.ResourceVersion {
					webhookChangedCh <- struct{}{}
				}
			},
			DeleteFunc: func(_ interface{}) {
				log.Debugf("************ DeleteFunc() in monitorValidatingWebhookConfig()")
				webhookChangedCh <- struct{}{}
			},
		},
	)
	go controller.Run(stopC)
	return webhookChangedCh
}

// Rebuild the mutatingwebhookconfiguration and save it for subsequent calls to createOrUpdateWebhookConfig.
func (wc *WebhookController) rebuildMutatingWebhookConfig() error {
	log.Debugf("*********************** enter rebuildMutatingWebhookConfig()")

	if len(wc.mutatingWebhookConfigFiles) == 0 || len(wc.mutatingWebhookConfigNames) == 0 {
		log.Error("no mutatingwebhook item is found")
		return fmt.Errorf("no mutatingwebhook item is found")
	}

	caCert, err := wc.getCACert()
	if err != nil {
		return err
	}
	// In the prototype, only one mutating webhook is rebuilt
	webhookConfig, err := rebuildMutatingWebhookConfigHelper(
		caCert,
		wc.mutatingWebhookConfigFiles[0],
		wc.mutatingWebhookConfigNames[0],
	)
	if err != nil {
		log.Errorf("failed to build mutatingwebhookconfiguration: %v", err)
		return err
	}
	wc.mutatingWebhookConfig = webhookConfig

	// print the mutatingwebhookconfiguration as YAML
	var configYAML string
	b, err := yaml.Marshal(wc.mutatingWebhookConfig)

	if err == nil {
		configYAML = string(b)
		log.Debugf("%v mutatingwebhookconfiguration is rebuilt: \n%v",
			wc.mutatingWebhookConfig.Name, configYAML)
		return nil
	}
	log.Errorf("error to marshal mutatingwebhookconfiguration %v: %v",
		wc.mutatingWebhookConfig.Name, err)
	return err
}

// Rebuild the validatingwebhookconfiguration and save it for subsequent calls to createOrUpdateWebhookConfig.
func (wc *WebhookController) rebuildValidatingWebhookConfig() error {
	log.Debugf("*********************** enter rebuildValidatingWebhookConfig()")
	if len(wc.validatingWebhookConfigFiles) == 0 || len(wc.validatingWebhookConfigNames) == 0 {
		log.Error("no validatingwebhook item is found")
		return fmt.Errorf("no validatingwebhook item is found")
	}

	caCert, err := wc.getCACert()
	if err != nil {
		return err
	}
	// In the prototype, only one validating webhook is rebuilt
	webhookConfig, err := rebuildValidatingWebhookConfigHelper(
		caCert,
		wc.validatingWebhookConfigFiles[0],
		wc.validatingWebhookConfigNames[0],
	)
	if err != nil {
		log.Errorf("failed to build validatingwebhookconfiguration: %v", err)
		return err
	}
	wc.validatingWebhookConfig = webhookConfig

	// print the validatingwebhookconfiguration as YAML
	var configYAML string
	b, err := yaml.Marshal(wc.validatingWebhookConfig)

	if err == nil {
		configYAML = string(b)
		log.Debugf("%v validatingwebhookconfiguration is rebuilt: \n%v",
			wc.validatingWebhookConfig.Name, configYAML)
		return nil
	}
	log.Errorf("error to marshal validatingwebhookconfiguration %v: %v",
		wc.validatingWebhookConfig.Name, err)
	return err
}

// Return the index of the first mutatingwebhook item. If not found, return -1.
func (wc *WebhookController) getMutatingWebhookItemIdx() int {
	for i, t := range WebhookTypes {
		if t == MutatingWebhook {
			return i
		}
	}
	return -1
}

// Return the index of the first validatingwebhook item. If not found, return -1.
func (wc *WebhookController) getValidatingWebhookItemIdx() int {
	for i, t := range WebhookTypes {
		if t == ValidatingWebhook {
			return i
		}
	}
	return -1
}

// Return the webhook secret name based on the service name
func (wc *WebhookController) getWebhookSecretNameFromSvcname(svcName string) string {
	return fmt.Sprintf("%s.%s", prefixWebhookSecretName, svcName)
}
