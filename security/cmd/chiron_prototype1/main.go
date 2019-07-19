package main

import (
	"os"
	"time"

	"istio.io/istio/security/pkg/pki/ca"
	"istio.io/istio/security/pkg/server/monitoring"

	"github.com/spf13/cobra"
	"github.com/spf13/cobra/doc"
	kubelib "istio.io/istio/pkg/kube"
	"istio.io/istio/security/pkg/cmd"
	cc "istio.io/istio/security/pkg/k8s/certificatecontroller"
	"istio.io/pkg/collateral"
	"istio.io/pkg/ctrlz"
	"istio.io/pkg/log"
	"istio.io/pkg/probe"
	"istio.io/pkg/version"
	_ "k8s.io/client-go/plugin/pkg/client/auth/gcp"
)

var (
	opts = cliOptions{
		logOptions:   log.DefaultOptions(),
		ctrlzOptions: ctrlz.DefaultOptions(),
	}

	rootCmd = &cobra.Command{
		Use:   "certificate_controller",
		Short: "Certificate Controller",
		Args:  cobra.ExactArgs(0),
		Run: func(cmd *cobra.Command, args []string) {
			runCertificateController()
		},
	}
)

type cliOptions struct {
	certificateNamespace string
	// Custom domain options, for control plane and special service accounts
	// comma separated list of SERVICE_ACCOUNT.NAMESPACE:DOMAIN
	customDNSNames string

	kubeConfigFile string

	// if set, namespaces require explicit labeling to have Certificate Controller generate secrets.
	explicitOptInRequired bool

	workloadCertTTL    time.Duration
	maxWorkloadCertTTL time.Duration
	// The length of certificate rotation grace period, configured as the ratio of the certificate TTL.
	// If workloadCertGracePeriodRatio is 0.2, and cert TTL is 24 hours, then the rotation will happen
	// after 24*(1-0.2) hours since the cert is issued.
	workloadCertGracePeriodRatio float32
	// The minimum grace period for workload cert rotation.
	workloadCertMinGracePeriod time.Duration

	// Whether to generate PKCS#8 private keys.
	pkcs8Keys bool

	// Monitoring port number
	monitoringPort int
	// Enable profiling in monitoring
	enableProfiling bool

	// The path to the file which indicates the liveness of the server by its existence.
	// This will be used for k8s liveness probe. If empty, it does nothing.
	// Currently, probe service is not supported yet.
	LivenessProbeOptions *probe.Options
	probeCheckInterval   time.Duration

	logOptions *log.Options
	// Currently, no topic is registered for ctrlz yet
	ctrlzOptions *ctrlz.Options

	// MutatingWebhook Configuration
	mutatingWebhookConfigName string
	mutatingWebhookName       string
}

func fatalf(template string, args ...interface{}) {
	if len(args) > 0 {
		log.Errorf(template, args...)
	} else {
		log.Errorf(template)
	}
	os.Exit(-1)
}

func init() {
	flags := rootCmd.Flags()
	flags.StringVar(&opts.certificateNamespace, "certificate-namespace", "istio-system",
		"Namespace for the certificates.")
	flags.BoolVar(&opts.explicitOptInRequired, "explicit-opt-in", false, "Specifies whether Certificate Controller requires "+
		"explicit opt-in for creating secrets. If set, only namespaces labeled with 'istio-managed=enabled' will "+
		"have secrets created. This feature is only available in key and certificates delivered through secret volume mount.")

	flags.StringVar(&opts.customDNSNames, "custom-dns-names", "",
		"A list of account.namespace:customdns, separated by comma. Each custom entry will be issued a certificate.")

	flags.StringVar(&opts.kubeConfigFile, "kube-config", "",
		"Specifies path to kubeconfig file. This must be specified when not running inside a Kubernetes pod.")

	// Monitoring configuration
	flags.IntVar(&opts.monitoringPort, "monitoring-port", 15021, "The port number for monitoring Chiron. "+
		"If unspecified, Chiron will disable monitoring.")
	flags.BoolVar(&opts.enableProfiling, "enable-profiling", false, "Enabling profiling when monitoring Chiron.")

	// Certificate signing configuration.
	flags.DurationVar(&opts.workloadCertTTL, "workload-cert-ttl", cmd.DefaultWorkloadCertTTL,
		"The TTL of issued workload certificates.")
	flags.DurationVar(&opts.maxWorkloadCertTTL, "max-workload-cert-ttl", cmd.DefaultMaxWorkloadCertTTL,
		"The max TTL of issued workload certificates.")
	flags.Float32Var(&opts.workloadCertGracePeriodRatio, "workload-cert-grace-period-ratio",
		cmd.DefaultWorkloadCertGracePeriodRatio, "The workload certificate rotation grace period, as a ratio of the "+
			"workload certificate TTL.")
	flags.DurationVar(&opts.workloadCertMinGracePeriod, "workload-cert-min-grace-period",
		cmd.DefaultWorkloadMinCertGracePeriod, "The minimum workload certificate rotation grace period.")

	flags.BoolVar(&opts.pkcs8Keys, "pkcs8-keys", false, "Whether to generate PKCS#8 private keys.")

	// MutatingWebhook configuration
	flags.StringVar(&opts.mutatingWebhookConfigName, "mutating-webhook-config-name", "istio-sidecar-injector",
		"SpName of the mutatingwebhookconfiguration resource in Kubernetes.")
	flags.StringVar(&opts.mutatingWebhookName, "mutating-webhook-name", "sidecar-injector.istio.io",
		"Name of the webhook entry in the webhook config.")

	rootCmd.AddCommand(version.CobraCommand())
	rootCmd.AddCommand(collateral.CobraCommand(rootCmd, &doc.GenManHeader{
		Title:   "Chiron: Istio Webhook Controller",
		Section: "Chiron: Istio Webhook Controller",
		Manual:  "Chiron: Istio Webhook Controller",
	}))
	rootCmd.AddCommand(cmd.NewProbeCmd())

	opts.logOptions.AttachCobraFlags(rootCmd)
	opts.ctrlzOptions.AttachCobraFlags(rootCmd)
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		log.Errora(err)
		os.Exit(1)
	}
}

func runCertificateController() {
	_, _ = ctrlz.Run(opts.ctrlzOptions, nil)

	if err := log.Configure(opts.logOptions); err != nil {
		log.Errorf("Failed to configure logging (%v)", err)
		os.Exit(1)
	}

	log.Debug("Enter runCertificateController()")

	webhooks := cc.ConstructCustomDNSNames(cc.WebhookServiceAccounts,
		cc.WebhookServiceNames, opts.certificateNamespace, opts.customDNSNames)
	log.Debugf("webhooks: %v", webhooks)

	k8sClient, err := kubelib.CreateClientset(opts.kubeConfigFile, "")
	if err != nil {
		log.Errorf("Could not create k8s clientset: %v", err)
		os.Exit(1)
	}
	log.Debugf("k8sClient: %v", k8sClient)

	log.Infof("Creating Kubernetes controller to write issued keys and certs into secret ...")
	stopCh := make(chan struct{})
	//ca := createCA(k8sClient.CoreV1())
	// TODO: change ca to use k8s CA
	var ca ca.CertificateAuthority

	// For workloads in K8s, we apply the configured workload cert TTL.
	sc, err := cc.NewSecretController(ca, opts.explicitOptInRequired,
		opts.workloadCertTTL,
		opts.workloadCertGracePeriodRatio, opts.workloadCertMinGracePeriod, false,
		k8sClient, k8sClient.CoreV1(), k8sClient.CertificatesV1beta1(), false, opts.pkcs8Keys, []string{opts.certificateNamespace}, webhooks,
		opts.certificateNamespace, opts.mutatingWebhookConfigName, opts.mutatingWebhookName)
	if err != nil {
		log.Errorf("Failed to create secret controller: %v", err)
		os.Exit(1)
	}

	// Release 1: get rid of dependency on Citadel. Webhook certificates are provisioned through
	// Chiron.
	// Release 2: manage WebhookConfiguration for Galley and SidecarInjector.

	// TODO: when the controller starts, creates the certificate and key of the secret for
	// Galley and Sidecar Injector. Add createSecret() to do this task.
	// TODO: Does it need a mutex for each public function to prevent race condition?
	// scrtDeleted(), scrtUpdated(), and createSecret() should have mutex if they run concurrently.
	// However, if createSecret() is only called once when the secret controller starts and
	// before scrtDeleted() and scrtUpdated() are set as callback, they will not have race condition.
	// But will someone use createSecret() at wrong places?

	// TODO: run a container in k8s for Cert. Controller. Check whether the default
	// service account of the pod is sufficient for Cert. Controller for the following operations:
	// - Send CSR for signing.
	// - Approve CSR, https://kubernetes.io/docs/tasks/tls/managing-tls-in-a-cluster/#approving-certificate-signing-requests
	// - Read signed certificate.
	// - Set a secret with certificate.
	// - Monitor secret expiration.
	// - What kind of RBAC config does a webhook needs?
	for _, sa := range cc.WebhookServiceAccounts {
		chain, key, err := sc.GenKeyCertK8sCA(sa, opts.certificateNamespace)
		if err != nil {
			log.Errorf("failed to create certificate for service account (%v) in namespace (%v): %v",
				sa, opts.certificateNamespace, err)
			os.Exit(1)
		}
		log.Debugf("certificate chain for service account (%v) in namespace (%v) is: %v",
			sa, opts.certificateNamespace, string(chain))
		log.Debugf("key for service account (%v) in namespace (%v) is: %v",
			sa, opts.certificateNamespace, string(key))
		if len(key) <= 0 || len(chain) <= 0 {
			log.Errorf("empty key or certificate for service account (%v) in namespace (%v)",
				sa, opts.certificateNamespace)
			os.Exit(1)
		}
	}

	// Run the controller to manage the lifecycles of webhook certificates and webhook configurations
	sc.Run(stopCh)
	defer sc.CaCertWatcher.Close()

	monitorErrCh := make(chan error)
	// Start the monitoring server.
	if opts.monitoringPort > 0 {
		monitor, mErr := monitoring.NewMonitor(opts.monitoringPort, opts.enableProfiling)
		if mErr != nil {
			fatalf("Unable to setup monitoring: %v", mErr)
		}
		go monitor.Start(monitorErrCh)
		log.Info("Chiron monitor has started.")
		defer monitor.Close()
	}

	// Blocking until receives error.
	for {
		select {
		case <-monitorErrCh:
			// TODO: does the controller exit when receiving an error?
			fatalf("Monitoring server error: %v", err)
		}
	}
}
