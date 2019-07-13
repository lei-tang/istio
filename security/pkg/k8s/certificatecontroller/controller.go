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

package certificatecontroller

import (
	"bytes"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"net"
	"k8s.io/api/admissionregistration/v1beta1"
	"k8s.io/client-go/kubernetes"
	"strings"
	"time"

	cert "k8s.io/api/certificates/v1beta1"
	certclient "k8s.io/client-go/kubernetes/typed/certificates/v1beta1"

	"k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
	corev1 "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/tools/cache"

	"istio.io/istio/pkg/spiffe"
	istioutil "istio.io/istio/pkg/util"
	"istio.io/istio/security/pkg/listwatch"
	"istio.io/istio/security/pkg/pki/ca"
	"istio.io/istio/security/pkg/pki/util"
	"istio.io/pkg/log"
)

/* #nosec: disable gas linter */
const (
	// The Istio secret annotation type
	IstioSecretType = "istio.io/key-and-cert"

	// The ID/name for the certificate chain file.
	CertChainID = "cert-chain.pem"
	// The ID/name for the private key file.
	PrivateKeyID = "key.pem"
	// The ID/name for the CA root certificate file.
	RootCertID = "root-cert.pem"
	// The key to specify corresponding service account in the annotation of K8s secrets.
	ServiceAccountNameAnnotationKey = "istio.io/service-account.name"

	secretNamePrefix   = "istio."
	// For debugging, set the resync period to be a shorter period.
	secretResyncPeriod = 10*time.Second
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

	// The path storing the CA certificate of the k8s apiserver
	caCertPath = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
	// caCertPath = "/usr/local/google/home/leitang/temp/cert-root.pem"
	//caCertPath = "/Users/leitang/temp/cert-root.pem"
)

type NetStatus int

const (
	Reachable NetStatus  = iota
	UnReachable
)

var (
	// TODO: change Citadel webhookServiceAccounts to use the webhook sa here.
	// ServiceAccount/DNS pair for generating DNS names in certificates.
	WebhookServiceAccounts = []string{
		"istio-protomutate-service-account",
// TODO: enable the following webhook service accounts after protomutate is ready
//		"istio-sidecar-injector-service-account",
//		"istio-galley-service-account",
	}

	WebhookServiceNames = []string{
		"protomutate",
// TODO: enable the following webhook service names after protomutate is ready
//		"istio-sidecar-injector",
//		"istio-galley",
	}

	// TODO: webhook namespaces should be input parameters
	WebhookNamespaces = []string{
		"istio-system",
		//		"istio-system",
		//		"istio-system",
	}
)

// DNSNameEntry stores the service name and namespace to construct the DNS id.
// Service accounts matching the ServiceName and Namespace will have additional DNS SANs:
// ServiceName.Namespace.svc, ServiceName.Namespace and optionall CustomDomain.
// This is intended for control plane and trusted services.
type DNSNameEntry struct {
	// ServiceName is the name of the service account to match
	ServiceName string

	// Namespace restricts to a specific namespace.
	Namespace string

	// CustomDomain allows adding a user-defined domain.
	CustomDomains []string
}

// SecretController manages the service accounts' secrets that contains Istio keys and certificates.
type SecretController struct {
	ca             ca.CertificateAuthority
	certTTL        time.Duration
	k8sClient      *kubernetes.Clientset
	core           corev1.CoreV1Interface
	minGracePeriod time.Duration
	// Length of the grace period for the certificate rotation.
	gracePeriodRatio float32

	// Whether the certificates are for dual-use clients (SAN+CN).
	dualUse bool

	// Whether the certificates are for CAs.
	forCA bool

	// If true, generate a PKCS#8 private key.
	pkcs8Key bool

	// whether ServiceAccount objects must explicitly opt-in for secrets.
	// Object explicit opt-in is based on "istio-inject" NS label value.
	// The default value should be read from a configmap and applied consistently
	// to all control plane operations
	explicitOptIn bool

	// The set of namespaces explicitly set for monitoring via commandline (an entry could be metav1.NamespaceAll)
	namespaces map[string]struct{}

	// DNS-enabled serviceAccount.namespace to service pair
	dnsNames map[string]*DNSNameEntry

	// Controller and store for service account objects.
	saController cache.Controller
	saStore      cache.Store

	// Controller and store for secret objects.
	scrtController cache.Controller
	scrtStore      cache.Store

	monitoring monitoringMetrics

	certClient certclient.CertificatesV1beta1Interface

	// The namespace of the webhook certificates
	namespace string


	// MutatingWebhookConfiguration
	mutatingWebhookConfigName string
	mutatingWebhookName string
}

// NewSecretController returns a pointer to a newly constructed SecretController instance.
func NewSecretController(ca ca.CertificateAuthority, requireOptIn bool, certTTL time.Duration,
	gracePeriodRatio float32, minGracePeriod time.Duration, dualUse bool, k8sClient *kubernetes.Clientset,
	core corev1.CoreV1Interface, certClient certclient.CertificatesV1beta1Interface, forCA bool, pkcs8Key bool, namespaces []string,
	dnsNames map[string]*DNSNameEntry, nameSpace, mutatingWebhookConfigName, mutatingWebhookName string) (*SecretController, error) {

	if gracePeriodRatio < 0 || gracePeriodRatio > 1 {
		return nil, fmt.Errorf("grace period ratio %f should be within [0, 1]", gracePeriodRatio)
	}
	if gracePeriodRatio < recommendedMinGracePeriodRatio || gracePeriodRatio > recommendedMaxGracePeriodRatio {
		log.Warnf("grace period ratio %f is out of the recommended window [%.2f, %.2f]",
			gracePeriodRatio, recommendedMinGracePeriodRatio, recommendedMaxGracePeriodRatio)
	}

	c := &SecretController{
		ca:               ca,
		certTTL:          certTTL,
		gracePeriodRatio: gracePeriodRatio,
		minGracePeriod:   minGracePeriod,
		dualUse:          dualUse,
		k8sClient:        k8sClient,
		core:             core,
		forCA:            forCA,
		pkcs8Key:         pkcs8Key,
		explicitOptIn:    requireOptIn,
		namespaces:       make(map[string]struct{}),
		dnsNames:         dnsNames,
		monitoring:       newMonitoringMetrics(),
		certClient:       certClient,
		namespace:        nameSpace,
		mutatingWebhookConfigName: mutatingWebhookConfigName,
		mutatingWebhookName: mutatingWebhookName,
	}

	for _, ns := range namespaces {
		c.namespaces[ns] = struct{}{}
	}

	saLW := listwatch.MultiNamespaceListerWatcher(namespaces, func(namespace string) cache.ListerWatcher {
		return &cache.ListWatch{
			ListFunc: func(options metav1.ListOptions) (runtime.Object, error) {
				return core.ServiceAccounts(namespace).List(options)
			},
			WatchFunc: func(options metav1.ListOptions) (watch.Interface, error) {
				return core.ServiceAccounts(namespace).Watch(options)
			},
		}
	})

	rehf := cache.ResourceEventHandlerFuncs{
		AddFunc:    c.saAdded,
		DeleteFunc: c.saDeleted,
	}
	c.saStore, c.saController = cache.NewInformer(saLW, &v1.ServiceAccount{}, time.Minute, rehf)

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


	return c, nil
}

// Run starts the SecretController until a value is sent to stopCh.
func (sc *SecretController) Run(stopCh chan struct{}) {
	log.Info("start running SecretController")
	// TODO: need to check that webhook endpoint and service entry are ready before
	// setting WebhookConfiguration.
	// For each webhook, a goroutine should check its TCP status and patch the webhook configuration.
	for {
		netStatus := checkTCPStatus("protomutate.istio-system", 443)
		if netStatus == Reachable {
			log.Info("protomutate service is reachable")
			break
		}
		log.Debugf("protomutate service is unreachable, check again later ...")
		time.Sleep(500 * time.Millisecond)
	}
	err := patchMutatingCertLoop(sc.k8sClient, sc.mutatingWebhookConfigName, sc.mutatingWebhookName, stopCh)
	if err != nil {
		// Abort if failed to patch mutating webhook
		log.Fatalf("failed to patch mutating webhook: %v", err)
	}

	//TODO: patchCertLoop() for ValidatingWebhook.

	go sc.scrtController.Run(stopCh)

	// saAdded calls upsertSecret to update and insert secret
	// it throws error if the secret cache is not synchronized, but the secret exists in the system
	cache.WaitForCacheSync(stopCh, sc.scrtController.HasSynced)

	go sc.saController.Run(stopCh)

}

// GetSecretName returns the secret name for a given service account name.
func GetSecretName(saName string) string {
	return secretNamePrefix + saName
}

// Determine if the object is "enabled" for Istio.
// Currently this looks at the list of watched namespaces and the object's namespace annotation
func (sc *SecretController) istioEnabledObject(obj metav1.Object) bool {
	if _, watched := sc.namespaces[obj.GetNamespace()]; watched || !sc.explicitOptIn {
		return true
	}

	const label = "istio-managed"
	enabled := !sc.explicitOptIn // for backward compatibility, Citadel always creates secrets
	// @todo this should be changed to false once we communicate behavior change and ensure customers
	// correctly mark their namespaces. Currently controlled via command line

	ns, err := sc.core.Namespaces().Get(obj.GetNamespace(), metav1.GetOptions{})
	if err != nil || ns == nil { // @todo handle errors? Unit tests mocks don't create NS, only secrets
		return enabled
	}

	if ns.Labels != nil {
		if v, ok := ns.Labels[label]; ok {
			switch strings.ToLower(v) {
			case "enabled", "enable", "true", "yes", "y":
				enabled = true
			case "disabled", "disable", "false", "no", "n":
				enabled = false
			default: // leave default unchanged
				break
			}
		}
	}
	return enabled
}

// Handles the event where a service account is added.
func (sc *SecretController) saAdded(obj interface{}) {
	acct := obj.(*v1.ServiceAccount)
	log.Debugf("Enter saAdded(), acct name: %v, acct namespace: %v", acct.GetName(), acct.GetNamespace())
	if !sc.isWebhookSA(acct.GetName(), acct.GetNamespace()) {
		// Only handle Webhook SA
		// TODO: 1. replace the hardcoded webhook namespace. 2. change Citadel to not handle Webhook SA
		return
	}
	if sc.istioEnabledObject(acct.GetObjectMeta()) {
		sc.upsertSecret(acct.GetName(), acct.GetNamespace())
	}
	sc.monitoring.ServiceAccountCreation.Inc()
}

// Handles the event where a service account is deleted.
func (sc *SecretController) saDeleted(obj interface{}) {
	acct := obj.(*v1.ServiceAccount)
	log.Debugf("Enter saDeleted(), acct name: %v, acct namespace: %v", acct.GetName(), acct.GetNamespace())
	if !sc.isWebhookSA(acct.GetName(), acct.GetNamespace()) {
		// Only handle Webhook SA
		return
	}
	sc.deleteSecret(acct.GetName(), acct.GetNamespace())
	sc.monitoring.ServiceAccountDeletion.Inc()
}

func (sc *SecretController) upsertSecret(saName, saNamespace string) {
	secret := ca.BuildSecret(saName, GetSecretName(saName), saNamespace, nil, nil, nil, nil, nil, IstioSecretType)

	_, exists, err := sc.scrtStore.Get(secret)
	if err != nil {
		log.Errorf("Failed to get secret from the store (error %v)", err)
	}

	if exists {
		// Do nothing for existing secrets. Rotating expiring certs are handled by the `scrtUpdated` method.
		return
	}

	// Now we know the secret does not exist yet. So we create a new one.
	//chain, key, err := sc.generateKeyAndCert(saName, saNamespace)
	chain, key, err := sc.GenKeyCertK8sCA(saName, saNamespace)
	if err != nil {
		log.Errorf("Failed to generate key and certificate for service account %q in namespace %q (error %v)",
			saName, saNamespace, err)
		return
	}
	rootCert, err := readCACert()
	if err != nil {
		return
	}
	secret.Data = map[string][]byte{
		CertChainID:  chain,
		PrivateKeyID: key,
		RootCertID:   rootCert,
	}

	// We retry several times when create secret to mitigate transient network failures.
	for i := 0; i < secretCreationRetry; i++ {
		_, err = sc.core.Secrets(saNamespace).Create(secret)
		if err == nil || errors.IsAlreadyExists(err) {
			if errors.IsAlreadyExists(err) {
				log.Infof("Istio secret for service account \"%s\" in namespace \"%s\" already exists", saName, saNamespace)
			}
			break
		} else {
			log.Errorf("Failed to create secret in attempt %v/%v, (error: %s)", i+1, secretCreationRetry, err)
		}
		time.Sleep(time.Second)
	}

	if err != nil && !errors.IsAlreadyExists(err) {
		log.Errorf("Failed to create secret for service account \"%s\"  (error: %s), retries %v times",
			saName, err, secretCreationRetry)
		return
	}

	log.Infof("Istio secret for service account \"%s\" in namespace \"%s\" has been created", saName, saNamespace)
}

func (sc *SecretController) deleteSecret(saName, saNamespace string) {
	err := sc.core.Secrets(saNamespace).Delete(GetSecretName(saName), nil)
	// kube-apiserver returns NotFound error when the secret is successfully deleted.
	if err == nil || errors.IsNotFound(err) {
		log.Infof("Istio secret for service account \"%s\" in namespace \"%s\" has been deleted", saName, saNamespace)
		return
	}

	log.Errorf("Failed to delete Istio secret for service account \"%s\" in namespace \"%s\" (error: %s)",
		saName, saNamespace, err)
}

func (sc *SecretController) scrtDeleted(obj interface{}) {
	scrt, ok := obj.(*v1.Secret)
	if !ok {
		log.Warnf("Failed to convert to secret object: %v", obj)
		return
	}

	saName := scrt.Annotations[ServiceAccountNameAnnotationKey]
	if sa, err := sc.core.ServiceAccounts(scrt.GetNamespace()).Get(saName, metav1.GetOptions{}); err == nil {
		log.Errorf("Re-create deleted Istio secret for existing service account %s.", saName)
		if sc.istioEnabledObject(sa.GetObjectMeta()) {
			sc.upsertSecret(saName, scrt.GetNamespace())
		}
		sc.monitoring.SecretDeletion.Inc()
	}
}

// TODO: remove this function since it has been replaced by GenKeyCertK8sCA().
func (sc *SecretController) generateKeyAndCert(saName string, saNamespace string) ([]byte, []byte, error) {
	id := spiffe.MustGenSpiffeURI(saNamespace, saName)
	if sc.dnsNames != nil {
		// Control plane components in same namespace.
		if e, ok := sc.dnsNames[saName]; ok {
			if e.Namespace == saNamespace {
				// Example: istio-pilot.istio-system.svc, istio-pilot.istio-system
				id += "," + fmt.Sprintf("%s.%s.svc", e.ServiceName, e.Namespace)
				id += "," + fmt.Sprintf("%s.%s", e.ServiceName, e.Namespace)
			}
		}
		// Custom adds more DNS entries using CLI
		if e, ok := sc.dnsNames[saName+"."+saNamespace]; ok {
			for _, d := range e.CustomDomains {
				id += "," + d
			}
		}
	}

	options := util.CertOptions{
		Host:       id,
		RSAKeySize: keySize,
		IsDualUse:  sc.dualUse,
		PKCS8Key:   sc.pkcs8Key,
	}

	csrPEM, keyPEM, err := util.GenCSR(options)
	if err != nil {
		log.Errorf("CSR generation error (%v)", err)
		sc.monitoring.CSRError.Inc()
		return nil, nil, err
	}

	certChainPEM := sc.ca.GetCAKeyCertBundle().GetCertChainPem()
	certPEM, signErr := sc.ca.Sign(csrPEM, strings.Split(id, ","), sc.certTTL, sc.forCA)
	if signErr != nil {
		log.Errorf("CSR signing error (%v)", signErr.Error())
		sc.monitoring.GetCertSignError(signErr.(*ca.Error).ErrorType()).Inc()
		return nil, nil, fmt.Errorf("CSR signing error (%v)", signErr.(*ca.Error))
	}
	certPEM = append(certPEM, certChainPEM...)

	return certPEM, keyPEM, nil
}

// scrtUpdated() is the callback function for update event. It handles
// the certificate rotations.
func (sc *SecretController) scrtUpdated(oldObj, newObj interface{}) {
	scrt, ok := newObj.(*v1.Secret)
	if !ok {
		log.Warnf("Failed to convert to secret object: %v", newObj)
		return
	}
	namespace := scrt.GetNamespace()
	name := scrt.GetName()
	// Only handle webhook secret update events
	if !sc.isWebhookSecret(name, namespace) {
		return
	}

	certBytes := scrt.Data[CertChainID]
	cert, err := util.ParsePemEncodedCertificate(certBytes)
	if err != nil {
		log.Warnf("Failed to parse certificates in secret %s/%s (error: %v), refreshing the secret.",
			namespace, name, err)
		if err = sc.refreshSecret(scrt); err != nil {
			log.Errora(err)
		}

		return
	}

	certLifeTimeLeft := time.Until(cert.NotAfter)
	certLifeTime := cert.NotAfter.Sub(cert.NotBefore)
	// TODO(myidpt): we may introduce a minimum gracePeriod, without making the config too complex.
	// Because time.Duration only takes int type, multiply gracePeriodRatio by 1000 and then divide it.
	gracePeriod := time.Duration(sc.gracePeriodRatio*1000) * certLifeTime / 1000
	if gracePeriod < sc.minGracePeriod {
		log.Warnf("gracePeriod (%v * %f) = %v is less than minGracePeriod %v. Apply minGracePeriod.",
			certLifeTime, sc.gracePeriodRatio, gracePeriod, sc.minGracePeriod)
		gracePeriod = sc.minGracePeriod
	}
	rootCertificate, err := readCACert()
	if err != nil {
		return
	}

	// Refresh the secret if 1) the certificate contained in the secret is about
	// to expire, or 2) the root certificate in the secret is different than the
	// one held by the ca (this may happen when the CA is restarted and
	// a new self-signed CA cert is generated).
	if certLifeTimeLeft < gracePeriod || !bytes.Equal(rootCertificate, scrt.Data[RootCertID]) {
		log.Infof("Refreshing secret %s/%s, either the leaf certificate is about to expire "+
			"or the root certificate is outdated", namespace, name)

		if err = sc.refreshSecret(scrt); err != nil {
			log.Errorf("Failed to update secret %s/%s (error: %s)", namespace, name, err)
		}
	}
}

// refreshSecret is an inner func to refresh cert secrets when necessary
func (sc *SecretController) refreshSecret(scrt *v1.Secret) error {
	namespace := scrt.GetNamespace()
	saName := scrt.Annotations[ServiceAccountNameAnnotationKey]

	// chain, key, err := sc.generateKeyAndCert(saName, namespace)
	chain, key, err := sc.GenKeyCertK8sCA(saName, namespace)
	if err != nil {
		return err
	}

	scrt.Data[CertChainID] = chain
	scrt.Data[PrivateKeyID] = key
	// TODO: change to get k8s CA root certificate
	caCert, err := readCACert()
	if err != nil {
		return err
	}
	scrt.Data[RootCertID] = caCert

	_, err = sc.core.Secrets(namespace).Update(scrt)
	return err
}

// Generate a certificate and key from k8s CA
func (sc *SecretController) GenKeyCertK8sCA(saName string, saNamespace string) ([]byte, []byte, error) {
	// 0. Generate a CSR
	// 1. Submit a CSR
	// 2. Approve a CSR
	// 3. Read the signed certificate
	// 4. Clean up the artifacts (e.g., delete CSR)
	csrCreated := false
	spiffeUri, err := spiffe.GenSpiffeURI(saNamespace, saName)
	if err != nil {
		log.Errorf("failed to generate a SPIFFE URI: %v", err)
		return nil, nil, err
	}
	id := spiffeUri
	if sc.dnsNames != nil {
		// Control plane components in same namespace.
		if e, ok := sc.dnsNames[saName]; ok {
			if e.Namespace == saNamespace {
				// Example: istio-pilot.istio-system.svc, istio-pilot.istio-system
				id += "," + fmt.Sprintf("%s.%s.svc", e.ServiceName, e.Namespace)
				id += "," + fmt.Sprintf("%s.%s", e.ServiceName, e.Namespace)
			}
		}
		// Custom adds more DNS entries using CLI
		if e, ok := sc.dnsNames[saName+"."+saNamespace]; ok {
			for _, d := range e.CustomDomains {
				id += "," + d
			}
		}
	}

	options := util.CertOptions{
		Host:       id,
		RSAKeySize: keySize,
		IsDualUse:  sc.dualUse,
		PKCS8Key:   sc.pkcs8Key,
	}

	csrPEM, keyPEM, err := util.GenCSR(options)
	if err != nil {
		log.Errorf("CSR generation error (%v)", err)
		sc.monitoring.CSRError.Inc()
		return nil, nil, err
	}
	log.Debugf("csrPem: %v", string(csrPEM))
	log.Debugf("keyPem: %v", keyPEM)

	// 1. Submit a CSR
	csrName := fmt.Sprintf("domain-%s-ns-%s-sa-%s", spiffe.GetTrustDomain(), saNamespace, saName)
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
			// TODO: determine the groups
			Groups:  []string{"system:authenticated"},
			Usages: []cert.KeyUsage{
				cert.UsageDigitalSignature,
				cert.UsageKeyEncipherment,
				cert.UsageServerAuth,
				cert.UsageClientAuth,
			},
		},
	}

	log.Debugf("create CSR (%v) ...", csrName)
	r, err := sc.certClient.CertificateSigningRequests().Create(k8sCSR)
	if err != nil {
		if !errors.IsAlreadyExists(err) {
			log.Debugf("failed to create CSR (%v): %v", csrName, err)
			return nil, nil, err
		}
		//Otherwise, delete the existing CSR and create again
		log.Debugf("delete an existing CSR: %v", csrName)
		err = sc.certClient.CertificateSigningRequests().Delete(csrName, nil)
		if err != nil {
			log.Errorf("failed to delete CSR (%v): %v", csrName, err)
			return nil, nil, err
		}
		log.Debugf("create CSR (%v) after the existing one was deleted", csrName)
		r, err = sc.certClient.CertificateSigningRequests().Create(k8sCSR)
		if err != nil {
			log.Debugf("failed to create CSR (%v): %v", csrName, err)
			return nil, nil, err
		}
	}
	log.Debugf("CSR (%v) is created, req.: %v", csrName, r)
	csrCreated = true

	// 2. Approve a CSR
	log.Debugf("approve CSR (%v) ...", csrName)
	r.Status.Conditions = append(r.Status.Conditions, cert.CertificateSigningRequestCondition{
		Type:    cert.CertificateApproved,
		Reason:  "k8s CSR is approved",
		Message: "The CSR is approved",
	})
	reqApproval, err := sc.certClient.CertificateSigningRequests().UpdateApproval(r)
	if err != nil {
		log.Debugf("failed to approve CSR (%v): %v", csrName, err)
		sc.cleanUpCertGen(csrName, csrCreated)
		return nil, nil, err
	}
	log.Debugf("CSR (%v) is approved, req.: %v", csrName, reqApproval)

	// 3. Read the signed certificate
	var reqSigned *cert.CertificateSigningRequest
	for i := 0; i < maxNumCertRead; i++ {
		time.Sleep(certReadInterval)
		reqSigned, err = sc.certClient.CertificateSigningRequests().Get(csrName, metav1.GetOptions{})
		if err != nil {
			log.Errorf("failed to get the CSR (%v): %v", csrName, err)
			sc.cleanUpCertGen(csrName, csrCreated)
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
		sc.cleanUpCertGen(csrName, csrCreated)
		return nil, nil, fmt.Errorf("failed to read the certificate for CSR (%v)", csrName)
	}

	// TODO: append the certificate chain to the signed certificate.
	// When Controller is running in a container,
	// it can read the ca cert from /var/run/secrets/kubernetes.io/serviceaccount/ca.crt.
	// The ca.crt is also in the default secret.

	// Read the CA certificate of the k8s apiserver
	caCert, err := readCACert()
	if err != nil {
		sc.cleanUpCertGen(csrName, csrCreated)
		return nil, nil, err
	}
	// Verify the certificate chain before returning the certificate (similar to
	// SPIRE agent calls golang certificate API to verify certificate chain):
	// - the verification will handle the case that the root certificate changes.
	roots := x509.NewCertPool()
	if roots == nil {
		sc.cleanUpCertGen(csrName, csrCreated)
		return nil, nil, fmt.Errorf("failed to create cert pool")
	}
	if ok := roots.AppendCertsFromPEM(caCert); !ok {
		sc.cleanUpCertGen(csrName, csrCreated)
		return nil, nil, fmt.Errorf("failed to append CA certificate")
	}
	certParsed, err := util.ParsePemEncodedCertificate(certPEM)
	if err != nil {
		log.Errorf("failed to parse the certificate: %v", err)
		sc.cleanUpCertGen(csrName, csrCreated)
		return nil, nil, fmt.Errorf("failed to parse the certificate: %v", err)
	}
	_, err = certParsed.Verify(x509.VerifyOptions{
		Roots:         roots,
	})
	if err != nil {
		log.Errorf("failed to verify the certificate chain: %v", err)
		sc.cleanUpCertGen(csrName, csrCreated)
		return nil, nil, fmt.Errorf("failed to verify the certificate chain: %v", err)
	}

	certChain := []byte{}
	certChain = append(certChain, certPEM...)
	certChain = append(certChain, caCert...)

	err = sc.cleanUpCertGen(csrName, csrCreated)
	return certChain, keyPEM, nil
}

func (sc *SecretController) cleanUpCertGen(csrName string, csrCreated bool) (error) {
	if csrCreated {
		// Delete CSR
		log.Debugf("delete CSR: %v", csrName)
		err := sc.certClient.CertificateSigningRequests().Delete(csrName, nil)
		if err != nil {
			log.Errorf("failed to delete CSR (%v): %v", csrName, err)
			return err
		}
	}
	return nil
}

// Return whether the input service account name is a Webhook service account
func (sc *SecretController) isWebhookSA(name, namespace string) (bool) {
	for _, n := range WebhookServiceAccounts {
		if n == name && namespace == sc.namespace {
			return true
		}
	}
	return false
}

// Return whether the input secret name is a Webhook secret
func (sc *SecretController) isWebhookSecret(name, namespace string) (bool) {
	for _, n := range WebhookServiceAccounts {
		if GetSecretName(n) == name && namespace == sc.namespace {
			return true
		}
	}
	return false
}

func readCACert() ([]byte, error) {
	caCert, err := ioutil.ReadFile(caCertPath)
	if err != nil {
		log.Errorf("failed to read CA cert, cert. path: %v, error: %v", caCertPath, err)
		return nil, fmt.Errorf("failed to read CA cert, cert. path: %v, error: %v", caCertPath, err)
	}
	return caCert, nil
}

func patchMutatingCertLoop(client *kubernetes.Clientset, webhookConfigName, webhookName string, stopCh <-chan struct{}) error {
	caCertPem, err := readCACert()
	// caCertPem, err := ioutil.ReadFile(flags.caCertFile)
	if err != nil {
		return err
	}

	// Chiron configures webhook configure
	if err = istioutil.PatchMutatingWebhookConfig(client.AdmissionregistrationV1beta1().MutatingWebhookConfigurations(),
		webhookConfigName, webhookName, caCertPem); err != nil {
		return err
	}

	shouldPatch := make(chan struct{})

	watchlist := cache.NewListWatchFromClient(
		client.AdmissionregistrationV1beta1().RESTClient(),
		"mutatingwebhookconfigurations",
		"",
		fields.ParseSelectorOrDie(fmt.Sprintf("metadata.name=%s", webhookConfigName)))

	_, controller := cache.NewInformer(
		watchlist,
		&v1beta1.MutatingWebhookConfiguration{},
		0,
		cache.ResourceEventHandlerFuncs{
			UpdateFunc: func(oldObj, newObj interface{}) {
				config := newObj.(*v1beta1.MutatingWebhookConfiguration)
				caCertPem, err := readCACert()
				if err != nil {
					log.Errorf("failed to read CA certificate: %v", err)
					return
				}
				// If the MutatingWebhookConfiguration changes and the CA bundle differs from current CA cert,
				// patch the CA bundle.
				// TODO: if CA cert changes, the CA bundle should be patched too.
				for i, w := range config.Webhooks {
					if w.Name == webhookName && !bytes.Equal(config.Webhooks[i].ClientConfig.CABundle, caCertPem) {
						log.Infof("Detected a change in CABundle, patching MutatingWebhookConfiguration again")
						shouldPatch <- struct{}{}
						break
					}
				}
			},
		},
	)
	go controller.Run(stopCh)

	go func() {
		for {
			select {
			case <-shouldPatch:
				doPatch(client, webhookConfigName, webhookName, caCertPem)
			}
		}
	}()

	return nil
}

func doPatch(client *kubernetes.Clientset, webhookConfigName, webhookName string, caCertPem []byte) {
	if err := istioutil.PatchMutatingWebhookConfig(client.AdmissionregistrationV1beta1().MutatingWebhookConfigurations(),
		webhookConfigName, webhookName, caCertPem); err != nil {
		log.Errorf("Patch webhook failed: %v", err)
	}
}

func checkTCPStatus(host string, port int) NetStatus {
	addr := fmt.Sprintf("%s:%d", host, port)
	conn, err := net.DialTimeout("tcp", addr, 1*time.Second)
	if err != nil {
		log.Debugf("DialTimeout() returns err: %v", err)
		// No connection yet, so no need to conn.Close()
		return UnReachable
	} else {
		defer conn.Close()
		return Reachable
	}
}