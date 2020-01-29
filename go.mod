module istio.io/istio

go 1.13

replace github.com/golang/glog => github.com/istio/glog v0.0.0-20190424172949-d7cfb6fa2ccd

replace k8s.io/klog => github.com/istio/klog v0.0.0-20190424230111-fb7481ea8bcf

replace github.com/spf13/viper => github.com/istio/viper v1.3.3-0.20190515210538-2789fed3109c

replace github.com/docker/docker => github.com/docker/engine v1.4.2-0.20191011211953-adfac697dc5b

require (
	cloud.google.com/go v0.41.0
	contrib.go.opencensus.io/exporter/prometheus v0.1.0
	contrib.go.opencensus.io/exporter/stackdriver v0.12.3
	contrib.go.opencensus.io/exporter/zipkin v0.1.1
	fortio.org/fortio v1.3.1
	github.com/Azure/go-autorest/autorest v0.9.4 // indirect
	github.com/DataDog/datadog-go v2.2.0+incompatible
	github.com/Masterminds/semver v1.4.2
	github.com/Masterminds/sprig v2.14.1+incompatible // indirect
	github.com/Microsoft/go-winio v0.4.14 // indirect
	github.com/alicebob/gopher-json v0.0.0-20180125190556-5a6b3ba71ee6 // indirect
	github.com/alicebob/miniredis v0.0.0-20180201100744-9d52b1fc8da9
	github.com/aokoli/goutils v1.0.1 // indirect
	github.com/apache/thrift v0.12.0 // indirect
	github.com/aws/aws-sdk-go v1.23.20
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/bmizerany/assert v0.0.0-20160611221934-b7ed37b82869 // indirect
	github.com/cactus/go-statsd-client v3.1.1+incompatible
	github.com/cenkalti/backoff v2.0.0+incompatible
	github.com/census-instrumentation/opencensus-proto v0.2.1
	github.com/circonus-labs/circonus-gometrics v2.3.1+incompatible
	github.com/circonus-labs/circonusllhist v0.1.4 // indirect
	github.com/cockroachdb/datadriven v0.0.0-20190809214429-80d97fb3cbaa // indirect
	github.com/codahale/hdrhistogram v0.0.0-20161010025455-3a0bb77429bd // indirect
	github.com/containerd/containerd v1.3.2 // indirect
	github.com/coreos/etcd v3.3.15+incompatible
	github.com/coreos/go-oidc v2.1.0+incompatible
	github.com/coreos/go-semver v0.3.0 // indirect
	github.com/coreos/go-systemd v0.0.0-20190321100706-95778dfbb74e // indirect
	github.com/creack/pty v1.1.7 // indirect
	github.com/cyphar/filepath-securejoin v0.2.2 // indirect
	github.com/d4l3k/messagediff v1.2.1 // indirect
	github.com/davecgh/go-spew v1.1.1
	github.com/dchest/siphash v1.1.0 // indirect
	github.com/docker/distribution v2.7.1+incompatible
	github.com/docker/docker v1.13.1
	github.com/docker/go-connections v0.4.0
	github.com/docker/spdystream v0.0.0-20181023171402-6480d4af844c // indirect
	github.com/docopt/docopt-go v0.0.0-20180111231733-ee0de3bc6815 // indirect
	github.com/dsnet/compress v0.0.1 // indirect
	github.com/dustin/go-humanize v1.0.0 // indirect
	github.com/elazarl/goproxy v0.0.0-20190630181448-f1e96bc0f4c5 // indirect
	github.com/elazarl/goproxy/ext v0.0.0-20190630181448-f1e96bc0f4c5 // indirect
	github.com/emicklei/go-restful v2.9.6+incompatible // indirect
	github.com/envoyproxy/go-control-plane v0.8.6
	github.com/envoyproxy/protoc-gen-validate v0.1.0 // indirect
	github.com/evanphx/json-patch v4.5.0+incompatible
	github.com/fluent/fluent-logger-golang v1.3.0
	github.com/frankban/quicktest v1.4.1 // indirect
	github.com/fsnotify/fsnotify v1.4.7
	github.com/garyburd/redigo v1.6.0 // indirect
	github.com/ghodss/yaml v1.0.0
	github.com/go-logr/logr v0.1.0
	github.com/go-logr/zapr v0.1.1 // indirect
	github.com/go-openapi/spec v0.19.5 // indirect
	github.com/go-openapi/swag v0.19.6 // indirect
	github.com/go-openapi/validate v0.19.5 // indirect
	github.com/go-redis/redis v6.10.2+incompatible
	github.com/gobwas/glob v0.2.3 // indirect
	github.com/gogo/protobuf v1.3.0
	github.com/golang/glog v0.0.0-20160126235308-23def4e6c14b
	github.com/golang/groupcache v0.0.0-20191027212112-611e8accdfc9 // indirect
	github.com/golang/protobuf v1.3.1
	github.com/golang/sync v0.0.0-20180314180146-1d60e4601c6f
	github.com/google/cel-go v0.2.0
	github.com/google/go-cmp v0.3.1
	github.com/google/go-github v17.0.0+incompatible
	github.com/google/go-querystring v1.0.0 // indirect
	github.com/google/uuid v1.1.1
	github.com/googleapis/gax-go v2.0.2+incompatible
	github.com/googleapis/gax-go/v2 v2.0.5
	github.com/googleapis/gnostic v0.3.0 // indirect
	github.com/gorilla/mux v1.7.3
	github.com/gorilla/websocket v1.4.1
	github.com/gregjones/httpcache v0.0.0-20190611155906-901d90724c79 // indirect
	github.com/grpc-ecosystem/go-grpc-middleware v1.0.1-0.20190118093823-f849b5445de4
	github.com/grpc-ecosystem/go-grpc-prometheus v1.2.0
	github.com/grpc-ecosystem/grpc-gateway v1.9.5 // indirect
	github.com/grpc-ecosystem/grpc-opentracing v0.0.0-20171214222146-0e7658f8ee99
	github.com/hashicorp/consul v1.3.1
	github.com/hashicorp/go-msgpack v0.5.5 // indirect
	github.com/hashicorp/go-multierror v1.0.0
	github.com/hashicorp/go-version v1.2.0
	github.com/hashicorp/golang-lru v0.5.4 // indirect
	github.com/hashicorp/serf v0.8.5 // indirect
	github.com/hashicorp/vault/api v1.0.3
	github.com/howeyc/fsnotify v0.9.0
	github.com/huandu/xstrings v1.2.1 // indirect
	github.com/imdario/mergo v0.3.7 // indirect
	github.com/istio.io/proxy/src/envoy/tcp/metadata_exchange/config v0.0.0
	github.com/json-iterator/go v1.1.9 // indirect
	github.com/kr/pretty v0.1.0
	github.com/kylelemons/godebug v1.1.0
	github.com/lestrrat-go/jwx v0.9.0
	github.com/magiconair/properties v1.8.1 // indirect
	github.com/mattn/go-isatty v0.0.12
	github.com/mattn/go-runewidth v0.0.2 // indirect
	github.com/mholt/archiver v3.1.1+incompatible
	github.com/mitchellh/copystructure v1.0.0
	github.com/mitchellh/go-homedir v1.1.0
	github.com/mitchellh/reflectwalk v1.0.1 // indirect
	github.com/morikuni/aec v1.0.0 // indirect
	github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822 // indirect
	github.com/natefinch/lumberjack v2.0.0+incompatible
	github.com/nwaples/rardecode v1.0.0 // indirect
	github.com/olekukonko/tablewriter v0.0.0-20170122224234-a0225b3f23b5 // indirect
	github.com/onsi/ginkgo v1.10.1 // indirect
	github.com/onsi/gomega v1.7.1
	github.com/open-policy-agent/opa v0.8.2
	github.com/opencontainers/image-spec v1.0.1 // indirect
	github.com/openshift/api v3.9.1-0.20191008181517-e4fd21196097+incompatible
	github.com/opentracing/opentracing-go v1.0.2
	github.com/openzipkin/zipkin-go v0.1.7
	github.com/pelletier/go-toml v1.3.0 // indirect
	github.com/philhofer/fwd v1.0.0 // indirect
	github.com/pierrec/lz4 v2.2.7+incompatible // indirect
	github.com/pkg/errors v0.8.1
	github.com/pmezard/go-difflib v1.0.0
	github.com/pquerna/cachecontrol v0.0.0-20180306154005-525d0eb5f91d // indirect
	github.com/prometheus/client_golang v1.0.0
	github.com/prometheus/client_model v0.0.0-20190812154241-14fe0d1b01d4
	github.com/prometheus/common v0.6.0
	github.com/prometheus/procfs v0.0.8 // indirect
	github.com/prometheus/prom2json v1.2.2
	github.com/prometheus/tsdb v0.7.1 // indirect
	github.com/ryanuber/go-glob v1.0.0
	github.com/satori/go.uuid v1.2.0
	github.com/soheilhy/cmux v0.1.4 // indirect
	github.com/spf13/cast v1.3.1 // indirect
	github.com/spf13/cobra v0.0.5
	github.com/spf13/jwalterweatherman v1.1.0 // indirect
	github.com/spf13/pflag v1.0.5
	github.com/spf13/viper v1.4.0
	github.com/stretchr/testify v1.4.0
	github.com/tinylib/msgp v1.0.2 // indirect
	github.com/tv42/httpunix v0.0.0-20191220191345-2ba4b9c3382c // indirect
	github.com/uber/jaeger-client-go v0.0.0-20190228190846-ecf2d03a9e80
	github.com/uber/jaeger-lib v2.0.0+incompatible // indirect
	github.com/urfave/cli v1.20.0 // indirect
	github.com/xi2/xz v0.0.0-20171230120015-48954b6210f8 // indirect
	github.com/xiang90/probing v0.0.0-20190116061207-43a291ad63a2 // indirect
	github.com/xlab/handysort v0.0.0-20150421192137-fb3537ed64a1 // indirect
	github.com/yashtewari/glob-intersection v0.0.0-20180206001645-7af743e8ec84 // indirect
	github.com/yl2chen/cidranger v0.0.0-20180214081945-928b519e5268
	github.com/yuin/gopher-lua v0.0.0-20180316054350-84ea3a3c79b3 // indirect
	go.etcd.io/bbolt v1.3.3 // indirect
	go.opencensus.io v0.22.2
	go.uber.org/atomic v1.4.0
	go.uber.org/multierr v1.1.0 // indirect
	go.uber.org/zap v1.10.0
	golang.org/x/exp v0.0.0-20191129062945-2f5052295587 // indirect
	golang.org/x/lint v0.0.0-20191125180803-fdd1cda4f05f // indirect
	golang.org/x/net v0.0.0-20191014212845-da9a3fd4c582
	golang.org/x/oauth2 v0.0.0-20190604053449-0f29369cfe45
	golang.org/x/time v0.0.0-20190308202827-9d24e82272b4
	golang.org/x/tools v0.0.0-20191216173652-a0e659d51361
	gomodules.xyz/jsonpatch/v2 v2.0.1 // indirect
	google.golang.org/api v0.15.0
	google.golang.org/appengine v1.6.5 // indirect
	google.golang.org/genproto v0.0.0-20190626174449-989357319d63
	google.golang.org/grpc v1.23.1
	gopkg.in/cheggaaa/pb.v1 v1.0.25 // indirect
	gopkg.in/d4l3k/messagediff.v1 v1.2.1
	gopkg.in/natefinch/lumberjack.v2 v2.0.0 // indirect
	gopkg.in/square/go-jose.v2 v2.3.1
	gopkg.in/yaml.v2 v2.2.7
	honnef.co/go/tools v0.0.1-2019.2.3 // indirect
	istio.io/gogo-genproto v0.0.0-20191024203824-d079cc8b1d55
	k8s.io/api v0.16.7-beta.0
	k8s.io/apiextensions-apiserver v0.15.10-beta.0
	k8s.io/apimachinery v0.16.7-beta.0
	k8s.io/cli-runtime v0.16.7-beta.0
	k8s.io/client-go v0.16.7-beta.0
	k8s.io/code-generator v0.17.2 // indirect
	k8s.io/helm v2.14.3+incompatible
	k8s.io/kubectl v0.16.7-beta.0
	k8s.io/utils v0.0.0-20191114184206-e782cd3c129f
	sigs.k8s.io/controller-runtime v0.2.0-alpha.0
	sigs.k8s.io/structured-merge-diff v1.0.1-0.20191108220359-b1b620dd3f06 // indirect
	sigs.k8s.io/testing_frameworks v0.1.2 // indirect
	sigs.k8s.io/yaml v1.1.0
	vbom.ml/util v0.0.0-20160121211510-db5cfe13f5cc // indirect
)

replace github.com/Azure/go-autorest/autorest => github.com/Azure/go-autorest/autorest v0.9.0

replace github.com/Azure/go-autorest/autorest/adal => github.com/Azure/go-autorest/autorest/adal v0.5.0

replace github.com/Azure/go-autorest => github.com/Azure/go-autorest v13.2.0+incompatible

replace github.com/istio.io/proxy/src/envoy/tcp/metadata_exchange/config v0.0.0 => ./pilot/pkg/metadata_exchange
