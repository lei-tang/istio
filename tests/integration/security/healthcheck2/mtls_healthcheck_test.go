//  Copyright 2019 Istio Authors
//
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
//  Unless required by applicable law or agreed to in writing, software
//  distributed under the License is distributed on an "AS IS" BASIS,
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  See the License for the specific language governing permissions and
//  limitations under the License.

// Package healthcheck contains a test to support kubernetes app health check when mTLS is turned on.
// https://github.com/istio/istio/issues/9150.
package healthcheck

import (
	"testing"

	"istio.io/istio/pkg/test/framework/components/apps"
	"istio.io/istio/pkg/test/framework/components/deployment"
	"istio.io/istio/pkg/test/framework/components/environment"
	"istio.io/istio/pkg/test/framework/components/namespace"
	"istio.io/istio/pkg/test/framework/components/pilot"

	"istio.io/istio/pkg/test/framework"
	"istio.io/istio/pkg/test/framework/components/istio"
)

var (
	ist istio.Instance
)

func TestMain(m *testing.M) {
	framework.NewSuite("mtls_healthcheck", m).
		RequireEnvironment(environment.Kube).
		Setup(istio.SetupOnKube(&ist, setupConfig)).
		Run()
}

func setupConfig(cfg *istio.Config) {
	if cfg == nil {
		return
	}
	cfg.Values["sidecarInjectorWebhook.rewriteAppHTTPProbe"] = "true"
	// New ones for Vault CA test
	cfg.Values["global.controlPlaneSecurityEnabled"] = "false"
	cfg.Values["global.mtls.enabled"] = "true"
	cfg.Values["global.sds.enabled"] = "true"
	cfg.Values["global.sds.udsPath"] = "unix:/var/run/sds/uds_path"
	cfg.Values["global.sds.useNormalJwt"] = "true"

	cfg.Values["nodeagent.enabled"] = "true"
	cfg.Values["nodeagent.image"] = "node-agent-k8s"
	cfg.Values["nodeagent.env.CA_ADDR"] = "https://35.233.249.249:8200"
	cfg.Values["nodeagent.env.CA_PROVIDER"] = "VaultCA"
	cfg.Values["nodeagent.env.VALID_TOKEN"] = "true"

	cfg.Values["nodeagent.env.VAULT_ADDR"] = "https://35.233.249.249:8200"
	cfg.Values["nodeagent.env.VAULT_AUTH_PATH"] = "auth/kubernetes/login"
	cfg.Values["nodeagent.env.VAULT_ROLE"] = "istio-cert"
	cfg.Values["nodeagent.env.VAULT_SIGN_CSR_PATH"] = "istio_ca/sign/istio-pki-role"
	cfg.Values["nodeagent.env.VAULT_TLS_ROOT_CERT"] = "-----BEGIN CERTIFICATE-----\nMIIC3jCCAcagAwIBAgIRAIcSFH1jneS0XPz5r2QDbigwDQYJKoZIhvcNAQELBQAw\nEDEOMAwGA1UEChMFVmF1bHQwIBcNMTgxMjI2MDkwMDU3WhgPMjExODEyMDIwOTAw\nNTdaMBAxDjAMBgNVBAoTBVZhdWx0MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIB\nCgKCAQEA2q5lfJCLAOTEjX3xV8qMLEX8zUQpd0AjD6zzOMzx51GVM7Plf7CJmaDq\nyloRz3zcrTEltHUrln5fvouvp4TetOlqEU979vvccnFLgXrSpn+Zt/EyjE0rUYY3\n5e2qxy9bP2E7zJSKONIT6zRDd2zUQGH3zUem1ZG0GFY1ZL5qFSOIy+PvuQ4u8HCa\n1CcnHmI613fVDbFbaxuF2G2MIwCZ/Fg6KBd9kgU7uCOvkbR4AtRe0ntwweIjOIas\nFiohPQzVY4obrYZiTV43HT4lGti7ySn2c96UnRSnmHLWyBb7cafd4WZN/t+OmYSd\nooxCVQ2Zqub6NlZ5OySYOz/0BJq6DQIDAQABozEwLzAOBgNVHQ8BAf8EBAMCBaAw\nDAYDVR0TAQH/BAIwADAPBgNVHREECDAGhwQj6fn5MA0GCSqGSIb3DQEBCwUAA4IB\nAQBORvUcW0wgg/Wo1aKFaZQuPPFVLjOZat0QpCJYNDhsSIO4Y0JS+Y1cEIkvXB3S\nQ3D7IfNP0gh1fhtP/d45LQSPqpyJF5vKWAvwa/LSPKpw2+Zys4oDahcH+SEKiQco\nIhkkHNEgC4LEKEaGvY4A8Cw7uWWquUJB16AapSSnkeD2vTcxErfCO59yR7yEWDa6\n8j6QNzmGNj2YXtT86+Mmedhfh65Rrh94mhAPQHBAdCNGCUwZ6zHPQ6Z1rj+x3Wm9\ngqpveVq2olloNbnLNmM3V6F9mqSZACgADmRqf42bixeHczkTfRDKThJcpY5U44vy\nw4Nm32yDWhD6AC68rDkXX68m\n-----END CERTIFICATE-----"

	cfg.Values["global.proxy.excludeIPRanges"] = "35.233.249.249/32"
}

// TestMtlsHealthCheck verifies Kubernetes HTTP health check can work when mTLS
// is enabled.
// Currently this test can only pass on Prow with a real GKE cluster, and fail
// on CircleCI with a Minikube. For more details, see https://github.com/istio/istio/issues/12754.
func TestMtlsHealthCheck(t *testing.T) {
	ctx := framework.NewContext(t)
	defer ctx.Done(t)
	ctx.RequireOrSkip(t, environment.Kube)

	ns := namespace.ClaimOrFail(t, ctx, "default")
	_, err := deployment.New(ctx, deployment.Config{
		Yaml: `apiVersion: "authentication.istio.io/v1alpha1"
kind: "Policy"
metadata:
  name: "mtls-strict-for-healthcheck"
spec:
  targets:
  - name: "healthcheck"
  peers:
    - mtls:
        mode: STRICT
`,
		Namespace: ns,
	})
	if err != nil {
		t.Error(err)
	}
	pilot := pilot.NewOrFail(t, ctx, pilot.Config{})
	aps := apps.NewOrFail(ctx, t, apps.Config{Pilot: pilot, AppParams: []apps.AppParam{
		{Name: "healthcheck"},
	}})
	aps.GetAppOrFail("healthcheck", t)
	// TODO(incfly): add a negative test once we have a per deployment annotation support for this feature.
}
