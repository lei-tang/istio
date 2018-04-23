// Copyright 2017 Istio Authors. All Rights Reserved.
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

package checkReport

import (
	"fmt"
	"encoding/base64"
	"testing"

	"istio.io/istio/mixer/test/client/env"
)

// Check attributes from a good GET request
const checkAttributesOkGet = `
{
  "context.protocol": "http",
  "mesh1.ip": "[1 1 1 1]",
  "mesh2.ip": "[0 0 0 0 0 0 0 0 0 0 255 255 204 152 189 116]",
  "mesh3.ip": "[0 1 0 0 0 0 0 0 0 0 0 0 0 0 0 8]",
  "request.host": "*",
  "request.path": "/echo",
  "request.time": "*",
  "request.useragent": "Go-http-client/1.1",
  "request.method": "GET",
  "request.scheme": "http",
  "source.uid": "POD11",
  "source.namespace": "XYZ11",
  "source.ip": "[127 0 0 1]",
  "source.port": "*",
  "target.name": "target-name",
  "target.user": "target-user",
  "target.uid": "POD222",
  "target.namespace": "XYZ222",
  "connection.mtls": false,
  "request.headers": {
     ":method": "GET",
     ":path": "/echo",
     ":authority": "*",
     "x-forwarded-proto": "http",
     "x-istio-attributes": "-",
     "x-request-id": "*"
  }
}
`

// Report attributes from a good GET request
const reportAttributesOkGet = `
{
  "context.protocol": "http",
  "mesh1.ip": "[1 1 1 1]",
  "mesh2.ip": "[0 0 0 0 0 0 0 0 0 0 255 255 204 152 189 116]",
  "mesh3.ip": "[0 1 0 0 0 0 0 0 0 0 0 0 0 0 0 8]",
  "request.host": "*",
  "request.path": "/echo",
  "request.time": "*",
  "request.useragent": "Go-http-client/1.1",
  "request.method": "GET",
  "request.scheme": "http",
  "source.uid": "POD11",
  "source.namespace": "XYZ11",
  "source.ip": "[127 0 0 1]",
  "source.port": "*",
  "destination.ip": "[127 0 0 1]",
  "destination.port": "*",
  "target.name": "target-name",
  "target.user": "target-user",
  "target.uid": "POD222",
  "target.namespace": "XYZ222",
  "connection.mtls": false,
  "check.cache_hit": false,
  "quota.cache_hit": false,
  "request.headers": {
     ":method": "GET",
     ":path": "/echo",
     ":authority": "*",
     "x-forwarded-proto": "http",
     "x-istio-attributes": "-",
     "x-request-id": "*"
  },
  "request.size": 0,
  "request.total_size": 517,
  "response.total_size": 99,
  "response.time": "*",
  "response.size": 0,
  "response.duration": "*",
  "response.code": 200,
  "response.headers": {
     "date": "*",
     "content-length": "0",
     ":status": "200",
     "server": "envoy"
  },
  "request.auth.audiences": "aud1",
  "request.auth.claims": {
     "iss": "issuer@foo.com", 
     "sub": "sub@foo.com",
     "aud": "aud1",
     "some-other-string-claims": "some-claims-kept"
  }
}
`

// Check attributes from a good POST request
const checkAttributesOkPost = `
{
  "context.protocol": "http",
  "mesh1.ip": "[1 1 1 1]",
  "mesh2.ip": "[0 0 0 0 0 0 0 0 0 0 255 255 204 152 189 116]",
  "mesh3.ip": "[0 1 0 0 0 0 0 0 0 0 0 0 0 0 0 8]",
  "request.host": "*",
  "request.path": "/echo",
  "request.time": "*",
  "request.useragent": "Go-http-client/1.1",
  "request.method": "POST",
  "request.scheme": "http",
  "source.uid": "POD11",
  "source.namespace": "XYZ11",
  "source.ip": "[127 0 0 1]",
  "source.port": "*",
  "target.name": "target-name",
  "target.user": "target-user",
  "target.uid": "POD222",
  "target.namespace": "XYZ222",
  "connection.mtls": false,
  "request.headers": {
     ":method": "POST",
     ":path": "/echo",
     ":authority": "*",
     "x-forwarded-proto": "http",
     "x-istio-attributes": "-",
     "x-request-id": "*"
  }
}
`

// Report attributes from a good POST request
const reportAttributesOkPost = `
{
  "context.protocol": "http",
  "mesh1.ip": "[1 1 1 1]",
  "mesh2.ip": "[0 0 0 0 0 0 0 0 0 0 255 255 204 152 189 116]",
  "mesh3.ip": "[0 1 0 0 0 0 0 0 0 0 0 0 0 0 0 8]",
  "request.host": "*",
  "request.path": "/echo",
  "request.time": "*",
  "request.useragent": "Go-http-client/1.1",
  "request.method": "POST",
  "request.scheme": "http",
  "source.uid": "POD11",
  "source.namespace": "XYZ11",
  "source.ip": "[127 0 0 1]",
  "source.port": "*",
  "destination.ip": "[127 0 0 1]",
  "destination.port": "*",
  "target.name": "target-name",
  "target.user": "target-user",
  "target.uid": "POD222",
  "target.namespace": "XYZ222",
  "connection.mtls": false,
  "check.cache_hit": false,
  "quota.cache_hit": false,
  "request.headers": {
     ":method": "POST",
     ":path": "/echo",
     ":authority": "*",
     "x-forwarded-proto": "http",
     "x-istio-attributes": "-",
     "x-request-id": "*"
  },
  "request.size": 12,
  "request.total_size": 342,
  "response.total_size": 134,
  "response.time": "*",
  "response.size": 12,
  "response.duration": "*",
  "response.code": 200,
  "response.headers": {
     "date": "*",
     "content-type": "text/plain",
     "content-length": "12",
     ":status": "200",
     "server": "envoy"
  }
}
`

// TODO: convert to v2, real clients use bootstrap v2 and all configs are switching !!!
// The envoy config template with Istio authn filter
const envoyConfTempl = `
{
  "listeners": [
    {
      "address": "tcp://0.0.0.0:{{.ServerPort}}",
      "bind_to_port": true,
      "filters": [
        {
          "type": "read",
          "name": "http_connection_manager",
          "config": {
            "codec_type": "auto",
            "stat_prefix": "ingress_http",
            "route_config": {
              "virtual_hosts": [
                {
                  "name": "backend",
                  "domains": ["*"],
                  "routes": [
                    {
                      "timeout_ms": 0,
                      "prefix": "/",
                      "cluster": "service1",
                      "opaque_config": {
{{.MixerRouteFlags}}
                      }
                    }
                  ]
                }
              ]
            },
            "access_log": [
              {
                "path": "{{.AccessLog}}"
              }
            ],
            "filters": [
{{.FaultFilter}}
              {
                "type": "decoder",
                "name": "istio_authn",
                "config": {
                  "policy": {
                    "origins": [
                      {
                        "jwt": {
                          "issuer": "issuer@foo.com",
                          "jwks_uri": "http://localhost:8081/"
                        }
                      }
                    ]
                  },
                  "jwt_output_payload_locations": {
                    "issuer@foo.com": "sec-istio-auth-jwt-output"
                  }
                }
              }, 
              {
                "type": "decoder",
                "name": "mixer",
                "config": {
{{.ServerConfig}}
                }
              },
              {
                "type": "decoder",
                "name": "router",
                "config": {}
              }
            ]
          }
        }
      ]
    },
    {
      "address": "tcp://0.0.0.0:{{.ClientPort}}",
      "bind_to_port": true,
      "filters": [
        {
          "type": "read",
          "name": "http_connection_manager",
          "config": {
            "codec_type": "auto",
            "stat_prefix": "ingress_http",
            "route_config": {
              "virtual_hosts": [
                {
                  "name": "backend",
                  "domains": ["*"],
                  "routes": [
                    {
                      "timeout_ms": 0,
                      "prefix": "/",
                      "cluster": "service2",
                      "opaque_config": {
                      }
                    }
                  ]
                }
              ]
            },
            "access_log": [
              {
                "path": "{{.AccessLog}}"
              }
            ],
            "filters": [
              {
                "type": "decoder",
                "name": "mixer",
                "config": {
{{.ClientConfig}}
                }
              },
              {
                "type": "decoder",
                "name": "router",
                "config": {}
              }
            ]
          }
        }
      ]
    },
    {
      "address": "tcp://0.0.0.0:{{.TCPProxyPort}}",
      "bind_to_port": true,
      "filters": [
        {
          "type": "both",
          "name": "mixer",
          "config": {
{{.TCPServerConfig}}
          }
        },
        {
          "type": "read",
          "name": "tcp_proxy",
          "config": {
            "stat_prefix": "tcp",
            "route_config": {
              "routes": [
                {
                  "cluster": "service1"
                }
              ]
            }
          }
        }
      ]
    }
  ],
  "admin": {
    "access_log_path": "/dev/stdout",
    "address": "tcp://0.0.0.0:{{.AdminPort}}"
  },
  "cluster_manager": {
    "clusters": [
      {
        "name": "service1",
        "connect_timeout_ms": 5000,
        "type": "strict_dns",
        "lb_type": "round_robin",
        "hosts": [
          {
            "url": "tcp://{{.Backend}}"
          }
        ]
      },
      {
        "name": "service2",
        "connect_timeout_ms": 5000,
        "type": "strict_dns",
        "lb_type": "round_robin",
        "hosts": [
          {
            "url": "tcp://localhost:{{.ServerPort}}"
          }
        ]
      },
      {
        "name": "mixer_server",
        "connect_timeout_ms": 5000,
        "type": "strict_dns",
	"circuit_breakers": {
           "default": {
	      "max_pending_requests": 10000,
	      "max_requests": 10000
            }
	},
        "lb_type": "round_robin",
        "features": "http2",
        "hosts": [
          {
            "url": "tcp://{{.MixerServer}}"
          }
        ]
      }
    ]
  }
}
`

const secIstioAuthUserInfoHeaderKey = "sec-istio-auth-jwt-output"

const secIstioAuthUserinfoHeaderValue = `
{
  "iss": "issuer@foo.com",
  "sub": "sub@foo.com",
  "aud": "aud1",
  "non-string-will-be-ignored": 1512754205,
  "some-other-string-claims": "some-claims-kept"
}
`

// Stats in Envoy proxy.
var expectedStats = map[string]int{
	"http_mixer_filter.total_blocking_remote_check_calls": 2,
	"http_mixer_filter.total_blocking_remote_quota_calls": 0,
	"http_mixer_filter.total_check_calls":                 2,
	"http_mixer_filter.total_quota_calls":                 0,
	"http_mixer_filter.total_remote_check_calls":          2,
	"http_mixer_filter.total_remote_quota_calls":          0,
	"http_mixer_filter.total_remote_report_calls":         2,
	"http_mixer_filter.total_report_calls":                2,
}

//TODO (lei-tang):
// - assign a port for authn test.
// - inject jwt payload from jwt-auth filter
// - add istio-authn filter to the filter chain
// - compare the authn attributes in the actual report matches those in the expected report
func TestAuthnCheckReportAttributes(t *testing.T) {
	s := env.NewTestSetupWithEnvoyConfig(env.CheckReportAttributesTest, envoyConfTempl, t)

	env.SetStatsUpdateInterval(s.MfConfig(), 1)
	if err := s.SetUp(); err != nil {
		t.Fatalf("Failed to setup test: %v", err)
	}
	defer s.TearDown()

	url := fmt.Sprintf("http://localhost:%d/echo", s.Ports().ClientProxyPort)

	// Issues a GET echo request with 0 size body
	tag := "OKGet"


	headers := map[string]string{}
	headers[secIstioAuthUserInfoHeaderKey] =
		base64.StdEncoding.EncodeToString([]byte(secIstioAuthUserinfoHeaderValue))

	//headers[env.FailHeader] = "Yes"
	//if _, _, err := env.HTTPGet(url); err != nil {
	if _, _, err := env.HTTPGetWithHeaders(url, headers); err != nil {
		t.Errorf("Failed in request %s: %v", tag, err)
	}
	//s.VerifyCheck(tag, checkAttributesOkGet)
	s.VerifyReport(tag, reportAttributesOkGet)

	// Issues a POST request.
	//tag = "OKPost"
	//if _, _, err := env.HTTPPost(url, "text/plain", "Hello World!"); err != nil {
	//	t.Errorf("Failed in request %s: %v", tag, err)
	//}
	//s.VerifyCheck(tag, checkAttributesOkPost)
	//s.VerifyReport(tag, reportAttributesOkPost)

	//if respStats, err := s.WaitForStatsUpdateAndGetStats(2); err == nil {
	//	s.VerifyStats(respStats, expectedStats)
	//} else {
	//	t.Errorf("Failed to get stats from Envoy %v", err)
	//}

	//// Verify that Mixer HTTP filter works properly when we change config version to V1 at Envoy.
	//s.SetMixerFilterConfVersion(env.MixerFilterConfigV1)
	//s.ReStartEnvoy()
	//
	//// Issues a POST request.
	//url = fmt.Sprintf("http://localhost:%d/echo", s.Ports().ClientProxyPort)
	//if _, _, err := env.HTTPPost(url, "text/plain", "Hello World!"); err != nil {
	//	t.Errorf("Failed in request %s: %v", tag, err)
	//}
	//s.VerifyCheck(tag, checkAttributesOkPost)
	//s.VerifyReport(tag, reportAttributesOkPost)
}
