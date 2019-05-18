package main

import (
	"istio.io/istio/security/pkg/pki/ca"
	"os"
	"time"

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
	// ServiceAccount/DNS pair for generating DNS names in certificates.
	webhookServiceAccounts = []string{
		"istio-sidecar-injector-service-account",
		"istio-galley-service-account",
	}
	webhookServiceNames = []string{
		"istio-sidecar-injector",
		"istio-galley",
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

	// The path to the file which indicates the liveness of the server by its existence.
	// This will be used for k8s liveness probe. If empty, it does nothing.
	// Currently, probe service is not supported yet.
	LivenessProbeOptions *probe.Options
	probeCheckInterval   time.Duration

	logOptions *log.Options
	// Currently, no topic is registered for ctrlz yet
	ctrlzOptions *ctrlz.Options
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


	rootCmd.AddCommand(version.CobraCommand())
	rootCmd.AddCommand(collateral.CobraCommand(rootCmd, &doc.GenManHeader{
		Title:   "Certificate Controller",
		Section: "Certificate Controller",
		Manual:  "Certificate Controller",
	}))
	rootCmd.AddCommand(cmd.NewProbeCmd())

	opts.logOptions.AttachCobraFlags(rootCmd)
	opts.ctrlzOptions.AttachCobraFlags(rootCmd)
}

func runCertificateController() {
	_, _ = ctrlz.Run(opts.ctrlzOptions, nil)

	if err := log.Configure(opts.logOptions); err != nil {
		log.Errorf("Failed to configure logging (%v)", err)
		os.Exit(1)
	}

	log.Debug("Enter runCertificateController")

	webhooks := cc.ConstructCustomDNSNames(webhookServiceAccounts,
		webhookServiceNames, opts.certificateNamespace, opts.customDNSNames)
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
		k8sClient.CoreV1(), k8sClient.CertificatesV1beta1(), false, opts.pkcs8Keys, []string{}, webhooks)
	if err != nil {
		log.Errorf("Failed to create secret controller: %v", err)
		os.Exit(1)
	}
	sc.Run(stopCh)

	for {
	}
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		log.Errora(err)
		os.Exit(1)
	}
}
