// Copyright Istio Authors
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

package features

import (
	"time"

	"github.com/golang/protobuf/ptypes"
	"github.com/golang/protobuf/ptypes/duration"

	"istio.io/istio/pkg/jwt"
	"istio.io/pkg/env"
)

const (
	// DefaultInboundCiphers for server side TLS configuration.
	DefaultInboundCiphers string = "ECDHE-ECDSA-AES256-GCM-SHA384," +
		"ECDHE-RSA-AES256-GCM-SHA384," +
		"ECDHE-ECDSA-AES128-GCM-SHA256," +
		"ECDHE-RSA-AES128-GCM-SHA256," +
		"AES256-GCM-SHA384," +
		"AES128-GCM-SHA256"
)

var (
	MaxConcurrentStreams = env.RegisterIntVar(
		"ISTIO_GPRC_MAXSTREAMS",
		100000,
		"Sets the maximum number of concurrent grpc streams.",
	).Get()

	TraceSampling = env.RegisterFloatVar(
		"PILOT_TRACE_SAMPLING",
		1.0,
		"Sets the mesh-wide trace sampling percentage. Should be 0.0 - 100.0. Precision to 0.01. "+
			"Default is 1.0.",
	).Get()

	// EnableIstioTags controls whether or not to configure Envoy with support for Istio-specific tags
	// in trace spans. This is a temporary flag for controlling the feature that will be replaced by
	// Telemetry API (or accepted as an always-on feature).
	EnableIstioTags = env.RegisterBoolVar(
		"PILOT_ENABLE_ISTIO_TAGS",
		true,
		"Determines whether or not trace spans generated by Envoy will include Istio-specific tags.",
	).Get()

	PushThrottle = env.RegisterIntVar(
		"PILOT_PUSH_THROTTLE",
		100,
		"Limits the number of concurrent pushes allowed. On larger machines this can be increased for faster pushes",
	).Get()

	// MaxRecvMsgSize The max receive buffer size of gRPC received channel of Pilot in bytes.
	MaxRecvMsgSize = env.RegisterIntVar(
		"ISTIO_GPRC_MAXRECVMSGSIZE",
		4*1024*1024,
		"Sets the max receive buffer size of gRPC stream in bytes.",
	).Get()

	// FilterGatewayClusterConfig controls if a subset of clusters(only those required) should be pushed to gateways
	// TODO enable by default once https://github.com/istio/istio/issues/28315 is resolved
	// Currently this may cause a bug when we go from N clusters -> 0 clusters -> N clusters
	FilterGatewayClusterConfig = env.RegisterBoolVar("PILOT_FILTER_GATEWAY_CLUSTER_CONFIG", false, "").Get()

	DebounceAfter = env.RegisterDurationVar(
		"PILOT_DEBOUNCE_AFTER",
		100*time.Millisecond,
		"The delay added to config/registry events for debouncing. This will delay the push by "+
			"at least this internal. If no change is detected within this period, the push will happen, "+
			" otherwise we'll keep delaying until things settle, up to a max of PILOT_DEBOUNCE_MAX.",
	).Get()

	DebounceMax = env.RegisterDurationVar(
		"PILOT_DEBOUNCE_MAX",
		10*time.Second,
		"The maximum amount of time to wait for events while debouncing. If events keep showing up with no breaks "+
			"for this time, we'll trigger a push.",
	).Get()

	EnableEDSDebounce = env.RegisterBoolVar(
		"PILOT_ENABLE_EDS_DEBOUNCE",
		true,
		"If enabled, Pilot will include EDS pushes in the push debouncing, configured by PILOT_DEBOUNCE_AFTER and PILOT_DEBOUNCE_MAX."+
			" EDS pushes may be delayed, but there will be fewer pushes. By default this is enabled",
	)

	// HTTP10 will add "accept_http_10" to http outbound listeners. Can also be set only for specific sidecars via meta.
	//
	// Alpha in 1.1, may become the default or be turned into a Sidecar API or mesh setting. Only applies to namespaces
	// where Sidecar is enabled.
	HTTP10 = env.RegisterBoolVar(
		"PILOT_HTTP10",
		false,
		"Enables the use of HTTP 1.0 in the outbound HTTP listeners, to support legacy applications.",
	).Get()

	// EnableMysqlFilter enables injection of `envoy.filters.network.mysql_proxy` in the filter chain.
	// Pilot injects this outbound filter if the service port name is `mysql`.
	EnableMysqlFilter = env.RegisterBoolVar(
		"PILOT_ENABLE_MYSQL_FILTER",
		false,
		"EnableMysqlFilter enables injection of `envoy.filters.network.mysql_proxy` in the filter chain.",
	).Get()

	// EnableRedisFilter enables injection of `envoy.filters.network.redis_proxy` in the filter chain.
	// Pilot injects this outbound filter if the service port name is `redis`.
	EnableRedisFilter = env.RegisterBoolVar(
		"PILOT_ENABLE_REDIS_FILTER",
		false,
		"EnableRedisFilter enables injection of `envoy.filters.network.redis_proxy` in the filter chain.",
	).Get()

	// UseRemoteAddress sets useRemoteAddress to true for side car outbound listeners so that it picks up the localhost
	// address of the sender, which is an internal address, so that trusted headers are not sanitized.
	UseRemoteAddress = env.RegisterBoolVar(
		"PILOT_SIDECAR_USE_REMOTE_ADDRESS",
		false,
		"UseRemoteAddress sets useRemoteAddress to true for side car outbound listeners.",
	).Get()

	// EnableThriftFilter enables injection of `envoy.filters.network.thrift_proxy` in the filter chain.
	// Pilot injects this outbound filter if the service port name is `thrift`.
	EnableThriftFilter = env.RegisterBoolVar(
		"PILOT_ENABLE_THRIFT_FILTER",
		false,
		"EnableThriftFilter enables injection of `envoy.filters.network.thrift_proxy` in the filter chain.",
	).Get()

	// SkipValidateTrustDomain tells the server proxy to not to check the peer's trust domain when
	// mTLS is enabled in authentication policy.
	SkipValidateTrustDomain = env.RegisterBoolVar(
		"PILOT_SKIP_VALIDATE_TRUST_DOMAIN",
		false,
		"Skip validating the peer is from the same trust domain when mTLS is enabled in authentication policy")

	EnableProtocolSniffingForOutbound = env.RegisterBoolVar(
		"PILOT_ENABLE_PROTOCOL_SNIFFING_FOR_OUTBOUND",
		true,
		"If enabled, protocol sniffing will be used for outbound listeners whose port protocol is not specified or unsupported",
	).Get()

	EnableProtocolSniffingForInbound = env.RegisterBoolVar(
		"PILOT_ENABLE_PROTOCOL_SNIFFING_FOR_INBOUND",
		true,
		"If enabled, protocol sniffing will be used for inbound listeners whose port protocol is not specified or unsupported",
	).Get()

	EnableWasmTelemetry = env.RegisterBoolVar(
		"ENABLE_WASM_TELEMETRY",
		false,
		"If enabled, Wasm-based telemetry will be enabled.",
	).Get()

	ScopeGatewayToNamespace = env.RegisterBoolVar(
		"PILOT_SCOPE_GATEWAY_TO_NAMESPACE",
		false,
		"If enabled, a gateway workload can only select gateway resources in the same namespace. "+
			"Gateways with same selectors in different namespaces will not be applicable.",
	).Get()

	// nolint
	InboundProtocolDetectionTimeout, InboundProtocolDetectionTimeoutSet = env.RegisterDurationVar(
		"PILOT_INBOUND_PROTOCOL_DETECTION_TIMEOUT",
		1*time.Second,
		"Protocol detection timeout for inbound listener",
	).Lookup()

	EnableHeadlessService = env.RegisterBoolVar(
		"PILOT_ENABLE_HEADLESS_SERVICE_POD_LISTENERS",
		true,
		"If enabled, for a headless service/stateful set in Kubernetes, pilot will generate an "+
			"outbound listener for each pod in a headless service. This feature should be disabled "+
			"if headless services have a large number of pods.",
	).Get()

	EnableRemoteJwks = env.RegisterBoolVar(
		"PILOT_JWT_ENABLE_REMOTE_JWKS",
		false,
		"If enabled, checks to see if the configured JwksUri in RequestAuthentication is a mesh cluster URL "+
			"and configures Remote Jwks to let Envoy fetch the Jwks instead of Istiod.",
	).Get()

	EnableEDSForHeadless = env.RegisterBoolVar(
		"PILOT_ENABLE_EDS_FOR_HEADLESS_SERVICES",
		false,
		"If enabled, for headless service in Kubernetes, pilot will send endpoints over EDS, "+
			"allowing the sidecar to load balance among pods in the headless service. This feature "+
			"should be enabled if applications access all services explicitly via a HTTP proxy port in the sidecar.",
	).Get()

	EnableDistributionTracking = env.RegisterBoolVar(
		"PILOT_ENABLE_CONFIG_DISTRIBUTION_TRACKING",
		true,
		"If enabled, Pilot will assign meaningful nonces to each Envoy configuration message, and allow "+
			"users to interrogate which envoy has which config from the debug interface.",
	).Get()

	DistributionHistoryRetention = env.RegisterDurationVar(
		"PILOT_DISTRIBUTION_HISTORY_RETENTION",
		time.Minute*1,
		"If enabled, Pilot will keep track of old versions of distributed config for this duration.",
	).Get()

	EnableEndpointSliceController = env.RegisterBoolVar(
		"PILOT_USE_ENDPOINT_SLICE",
		false,
		"If enabled, Pilot will use EndpointSlices as the source of endpoints for Kubernetes services. "+
			"By default, this is false, and Endpoints will be used. This requires the Kubernetes EndpointSlice controller to be enabled. "+
			"Currently this is mutual exclusive - either Endpoints or EndpointSlices will be used",
	).Get()

	EnableSDSServer = env.RegisterBoolVar(
		"ISTIOD_ENABLE_SDS_SERVER",
		true,
		"If enabled, Istiod will serve SDS for credentialName secrets (rather than in-proxy). "+
			"To ensure proper security, PILOT_ENABLE_XDS_IDENTITY_CHECK=true is required as well.",
	).Get()

	EnableAnalysis = env.RegisterBoolVar(
		"PILOT_ENABLE_ANALYSIS",
		false,
		"If enabled, pilot will run istio analyzers and write analysis errors to the Status field of any "+
			"Istio Resources",
	).Get()

	EnableStatus = env.RegisterBoolVar(
		"PILOT_ENABLE_STATUS",
		false,
		"If enabled, pilot will update the CRD Status field of all istio resources with reconciliation status.",
	).Get()

	StatusQPS = env.RegisterFloatVar(
		"PILOT_STATUS_QPS",
		100,
		"If status is enabled, controls the QPS with which status will be updated.  "+
			"See https://godoc.org/k8s.io/client-go/rest#Config QPS",
	).Get()

	StatusBurst = env.RegisterIntVar(
		"PILOT_STATUS_BURST",
		500,
		"If status is enabled, controls the Burst rate with which status will be updated.  "+
			"See https://godoc.org/k8s.io/client-go/rest#Config Burst",
	).Get()

	// IstiodServiceCustomHost allow user to bring a custom address for istiod server
	// for examples: istiod.mycompany.com
	IstiodServiceCustomHost = env.RegisterStringVar("ISTIOD_CUSTOM_HOST", "",
		"Custom host name of istiod that istiod signs the server cert.")

	PilotCertProvider = env.RegisterStringVar("PILOT_CERT_PROVIDER", "istiod",
		"The provider of Pilot DNS certificate.")

	JwtPolicy = env.RegisterStringVar("JWT_POLICY", jwt.PolicyThirdParty,
		"The JWT validation policy.")

	// Default request timeout for virtual services if a timeout is not configured in virtual service. It defaults to zero
	// which disables timeout when it is not configured, to preserve the current behavior.
	defaultRequestTimeoutVar = env.RegisterDurationVar(
		"ISTIO_DEFAULT_REQUEST_TIMEOUT",
		0*time.Millisecond,
		"Default Http and gRPC Request timeout",
	)

	DefaultRequestTimeout = func() *duration.Duration {
		return ptypes.DurationProto(defaultRequestTimeoutVar.Get())
	}()

	EnableServiceApis = env.RegisterBoolVar("PILOT_ENABLED_SERVICE_APIS", true,
		"If this is set to true, support for Kubernetes gateway-api (github.com/kubernetes-sigs/gateway-api) will "+
			" be enabled. In addition to this being enabled, the gateway-api CRDs need to be installed.").Get()

	EnableVirtualServiceDelegate = env.RegisterBoolVar(
		"PILOT_ENABLE_VIRTUAL_SERVICE_DELEGATE",
		true,
		"If set to false, virtualService delegate will not be supported.").Get()

	ClusterName = env.RegisterStringVar("CLUSTER_ID", "Kubernetes",
		"Defines the cluster and service registry that this Istiod instance is belongs to").Get()

	ExternalIstiod = env.RegisterBoolVar("EXTERNAL_ISTIOD", false,
		"If this is set to true, one Istiod will control remote clusters including CA.").Get()

	EnableCAServer = env.RegisterBoolVar("ENABLE_CA_SERVER", true,
		"If this is set to false, will not create CA server in istiod.").Get()

	EnableDebugOnHTTP = env.RegisterBoolVar("ENABLE_DEBUG_ON_HTTP", true,
		"If this is set to false, the debug interface will not be ebabled on Http, recommended for production").Get()

	EnableUnsafeAdminEndpoints = env.RegisterBoolVar("UNSAFE_ENABLE_ADMIN_ENDPOINTS", false,
		"If this is set to true, dangerous admin endpoins will be exposed on the debug interface. Not recommended for production.").Get()

	XDSAuth = env.RegisterBoolVar("XDS_AUTH", true,
		"If true, will authenticate XDS clients.").Get()

	EnableXDSIdentityCheck = env.RegisterBoolVar(
		"PILOT_ENABLE_XDS_IDENTITY_CHECK",
		true,
		"If enabled, pilot will authorize XDS clients, to ensure they are acting only as namespaces they have permissions for.",
	).Get()

	EnableServiceEntrySelectPods = env.RegisterBoolVar("PILOT_ENABLE_SERVICEENTRY_SELECT_PODS", true,
		"If enabled, service entries with selectors will select pods from the cluster. "+
			"It is safe to disable it if you are quite sure you don't need this feature").Get()

	EnableK8SServiceSelectWorkloadEntries = env.RegisterBoolVar("PILOT_ENABLE_K8S_SELECT_WORKLOAD_ENTRIES", true,
		"If enabled, Kubernetes services with selectors will select workload entries with matching labels. "+
			"It is safe to disable it if you are quite sure you don't need this feature").Get()

	InjectionWebhookConfigName = env.RegisterStringVar("INJECTION_WEBHOOK_CONFIG_NAME", "istio-sidecar-injector",
		"Name of the mutatingwebhookconfiguration to patch, if istioctl is not used.")

	SpiffeBundleEndpoints = env.RegisterStringVar("SPIFFE_BUNDLE_ENDPOINTS", "",
		"The SPIFFE bundle trust domain to endpoint mappings. Istiod retrieves the root certificate from each SPIFFE "+
			"bundle endpoint and uses it to verify client certifiates from that trust domain. The endpoint must be "+
			"compliant to the SPIFFE Bundle Endpoint standard. For details, please refer to "+
			"https://github.com/spiffe/spiffe/blob/master/standards/SPIFFE_Trust_Domain_and_Bundle.md . "+
			"No need to configure this for root certificates issued via Istiod or web-PKI based root certificates. "+
			"Use || between <trustdomain, endpoint> tuples. Use | as delimiter between trust domain and endpoint in "+
			"each tuple. For example: foo|https://url/for/foo||bar|https://url/for/bar").Get()

	EnableXDSCaching = env.RegisterBoolVar("PILOT_ENABLE_XDS_CACHE", true,
		"If true, Pilot will cache XDS responses.").Get()

	EnableXDSCacheMetrics = env.RegisterBoolVar("PILOT_XDS_CACHE_STATS", false,
		"If true, Pilot will collect metrics for XDS cache efficiency.").Get()

	XDSCacheMaxSize = env.RegisterIntVar("PILOT_XDS_CACHE_SIZE", 20000,
		"The maximum number of cache entries for the XDS cache.").Get()

	AllowMetadataCertsInMutualTLS = env.RegisterBoolVar("PILOT_ALLOW_METADATA_CERTS_DR_MUTUAL_TLS", false,
		"If true, Pilot will allow certs specified in Metadata to override DR certs in MUTUAL TLS mode. "+
			"This is only enabled for migration and will be removed soon.").Get()

	// EnableLegacyFSGroupInjection has first-party-jwt as allowed because we only
	// need the fsGroup configuration for the projected service account volume mount,
	// which is only used by first-party-jwt. The installer will automatically
	// configure this on Kubernetes 1.19+.
	EnableLegacyFSGroupInjection = env.RegisterBoolVar("ENABLE_LEGACY_FSGROUP_INJECTION", JwtPolicy.Get() != jwt.PolicyFirstParty,
		"If true, Istiod will set the pod fsGroup to 1337 on injection. This is required for Kubernetes 1.18 and older "+
			`(see https://github.com/kubernetes/kubernetes/issues/57923 for details) unless JWT_POLICY is "first-party-jwt".`).Get()

	XdsPushSendTimeout = env.RegisterDurationVar(
		"PILOT_XDS_SEND_TIMEOUT",
		5*time.Second,
		"The timeout to send the XDS configuration to proxies. After this timeout is reached, Pilot will discard that push.",
	).Get()

	EndpointTelemetryLabel = env.RegisterBoolVar("PILOT_ENDPOINT_TELEMETRY_LABEL", true,
		"If true, pilot will add telemetry related metadata to Endpoint resource, which will be consumed by telemetry filter.",
	).Get()

	WorkloadEntryAutoRegistration = env.RegisterBoolVar("PILOT_ENABLE_WORKLOAD_ENTRY_AUTOREGISTRATION", true,
		"Enables auto-registering WorkloadEntries based on associated WorkloadGroups upon XDS connection by the workload.").Get()

	WorkloadEntryCleanupGracePeriod = env.RegisterDurationVar("PILOT_WORKLOAD_ENTRY_GRACE_PERIOD", 10*time.Second,
		"The amount of time an auto-registered workload can remain disconnected from all Pilot instances before the "+
			"associated WorkloadEntry is cleaned up.").Get()

	WorkloadEntryHealthChecks = env.RegisterBoolVar("PILOT_ENABLE_WORKLOAD_ENTRY_HEALTHCHECKS", true,
		"Enables automatic health checks of WorkloadEntries based on the config provided in the associated WorkloadGroup").Get()

	WorkloadEntryCrossCluster = env.RegisterBoolVar("PILOT_ENABLE_CROSS_CLUSTER_WORKLOAD_ENTRY", false,
		"If enabled, pilot will read WorkloadEntry from other clusters, selectable by Services in that cluster.").Get()

	EnableFlowControl = env.RegisterBoolVar(
		"PILOT_ENABLE_FLOW_CONTROL",
		false,
		"If enabled, pilot will wait for the completion of a receive operation before"+
			"executing a push operation. This is a form of flow control and is useful in"+
			"environments with high rates of push requests to each gateway. By default,"+
			"this is false.").Get()

	FlowControlTimeout = env.RegisterDurationVar(
		"PILOT_FLOW_CONTROL_TIMEOUT",
		15*time.Second,
		"If set, the max amount of time to delay a push by. Depends on PILOT_ENABLE_FLOW_CONTROL.",
	).Get()

	EnableDestinationRuleInheritance = env.RegisterBoolVar(
		"PILOT_ENABLE_DESTINATION_RULE_INHERITANCE",
		false,
		"If set, workload specific DestinationRules will inherit configurations settings from mesh and namespace level rules",
	).Get()

	StatusMaxWorkers = env.RegisterIntVar("PILOT_STATUS_MAX_WORKERS", 100, "The maximum number of workers"+
		" Pilot will use to keep configuration status up to date.  Smaller numbers will result in higher status latency, "+
		"but larger numbers may impact CPU in high scale environments.")

	WasmRemoteLoadConversion = env.RegisterBoolVar("ISTIO_AGENT_ENABLE_WASM_REMOTE_LOAD_CONVERSION", true,
		"If enabled, Istio agent will intercept ECDS resource update, downloads Wasm module, "+
			"and replaces Wasm module remote load with downloaded local module file.").Get()

	PilotJwtPubKeyRefreshInterval = env.RegisterDurationVar(
		"PILOT_JWT_PUB_KEY_REFRESH_INTERVAL",
		20*time.Minute,
		"The interval for istiod to fetch the jwks_uri for the jwks public key.",
	).Get()

	EnableInboundPassthrough = env.RegisterBoolVar(
		"PILOT_ENABLE_INBOUND_PASSTHROUGH",
		true,
		"If enabled, inbound clusters will be configured as ORIGINAL_DST clusters. When disabled, "+
			"requests are always sent to localhost. The primary implication of this is that when enabled, binding to POD_IP "+
			"will work while localhost will not; when disable, bind to POD_IP will not work, while localhost will. "+
			"The enabled behavior matches the behavior without Istio enabled at all; this flag exists only for backwards compatibility. "+
			"Regardless of this setting, the configuration can be overridden with the Sidecar.Ingress.DefaultEndpoint configuration.",
	).Get()

	StripHostPort = env.RegisterBoolVar("ISTIO_GATEWAY_STRIP_HOST_PORT", false,
		"If enabled, Gateway will remove any port from host/authority header "+
			"before any processing of request by HTTP filters or routing.").Get()

	// EnableUnsafeAssertions enables runtime checks to test assertions in our code. This should never be enabled in
	// production; when assertions fail Istio will panic.
	EnableUnsafeAssertions = env.RegisterBoolVar(
		"UNSAFE_PILOT_ENABLE_RUNTIME_ASSERTIONS",
		false,
		"If enabled, addition runtime asserts will be performed. "+
			"These checks are both expensive and panic on failure. As a result, this should be used only for testing.",
	).Get()

	TLSInboundCipherSuites = env.RegisterStringVar("TLS_INBOUND_CIPHER_SUITES", DefaultInboundCiphers,
		"The cipher suites for inbound TLS connections, delimited by comma.").Get()
)

// UnsafeFeaturesEnabled returns true if any unsafe features are enabled.
func UnsafeFeaturesEnabled() bool {
	return EnableUnsafeAdminEndpoints || EnableUnsafeAssertions
}
