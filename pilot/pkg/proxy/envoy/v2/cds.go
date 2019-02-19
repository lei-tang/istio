// Copyright 2018 Istio Authors
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

package v2

import (
	"fmt"

	"github.com/golang/protobuf/proto"

	xdsapi "github.com/envoyproxy/go-control-plane/envoy/api/v2"
	"github.com/gogo/protobuf/types"
	"github.com/prometheus/client_golang/prometheus"

	"istio.io/istio/pilot/pkg/model"
)

// clusters aggregate a DiscoveryResponse for pushing.
func (con *XdsConnection) clusters(response []*xdsapi.Cluster) *xdsapi.DiscoveryResponse {
	out := &xdsapi.DiscoveryResponse{
		// All resources for CDS ought to be of the type ClusterLoadAssignment
		TypeUrl: ClusterType,

		// Pilot does not really care for versioning. It always supplies what's currently
		// available to it, irrespective of whether Envoy chooses to accept or reject CDS
		// responses. Pilot believes in eventual consistency and that at some point, Envoy
		// will begin seeing results it deems to be good.
		VersionInfo: versionInfo(),
		Nonce:       nonce(),
	}

	for _, c := range response {
		cc, _ := types.MarshalAny(c)
		out.Resources = append(out.Resources, *cc)
	}

	return out
}

func (s *DiscoveryServer) pushCds(con *XdsConnection, push *model.PushContext, version string) error {
	adsLog.Infof("***** Enter pushCds()")

	// TODO: Modify interface to take services, and config instead of making library query registry
	rawClusters, err := s.generateRawClusters(con.modelNode, push)
	if err != nil {
		return err
	}
	if s.DebugConfigs {
		con.CDSClusters = rawClusters
	}

	response := con.clusters(rawClusters)

	err = con.send(response)

	if err != nil {
		adsLog.Warnf("CDS: Send failure %s: %v", con.ConID, err)
		pushes.With(prometheus.Labels{"type": "cds_senderr"}).Add(1)
		return err
	}
	pushes.With(prometheus.Labels{"type": "cds"}).Add(1)

	adsLog.Infof("***** Exit pushCds()")
	return nil
}

func (s *DiscoveryServer) generateRawClusters(node *model.Proxy, push *model.PushContext) ([]*xdsapi.Cluster, error) {
	adsLog.Infof("***** Enter generateRawClusters() with node metadata %v", node.Metadata)

	rawClusters, err := s.ConfigGenerator.BuildClusters(s.Env, node, push)
	if err != nil {
		adsLog.Warnf("CDS: Failed to generate clusters for node %s: %v", node.ID, err)
		pushes.With(prometheus.Labels{"type": "cds_builderr"}).Add(1)
		return nil, err
	}

	for _, c := range rawClusters {
		SetSdsTokenPathFromProxyMetadata(c, node)
		if err = c.Validate(); err != nil {
			retErr := fmt.Errorf("CDS: Generated invalid cluster for node %v: %v", node, err)
			adsLog.Errorf("CDS: Generated invalid cluster for node %s: %v, %v", node.ID, err, c)
			pushes.With(prometheus.Labels{"type": "cds_builderr"}).Add(1)
			totalXDSInternalErrors.Add(1)
			// Generating invalid clusters is a bug.
			// Panic instead of trying to recover from that, since we can't
			// assume anything about the state.
			panic(retErr.Error())
		}
	}

	for idx, c := range rawClusters {
		adsLog.Infof("***** rawClusters %v: %v", idx, proto.MarshalTextString(c))
	}

	adsLog.Infof("***** Exit generateRawClusters() with node metadata %v", node.Metadata)
	return rawClusters, nil
}

// Set the SDS token path if SDS_TOKEN_PATH is defined in the proxy metadata
func SetSdsTokenPathFromProxyMetadata(c *xdsapi.Cluster, node *model.Proxy) {
	//TODO (lei-tang):
	// 1. add unit test
	// 2. test with httpbin and sleep for mTLS
	// - When sleep curl httpbin, an error occurs:
	// - solve the problem of sleep: SSL error: 268435581:SSL routines:OPENSSL_internal:CERTIFICATE_VERIFY_FAILED
	// - solve the problem of httpbin: SSL error: 268436502:SSL routines:OPENSSL_internal:SSLV3_ALERT_CERTIFICATE_UNKNOWN
	// - The problem is resolved by let httpbin and sleep to run using a service account called "vault-citadel-sa".
	// The service account is configured in the deployment.
	// The problem caused by secure naming (service name validation).
	// - client asks Pilot what the server's service account is. Pilot put verify_subject_alt_name of the server (httpbin)
	// in the CDS of client (sleep).
	//combined_validation_context {
	//	default_validation_context {
	//		verify_subject_alt_name: "spiffe://cluster.local/ns/default/sa/vault-citadel-sa"
	//	}
	//}
	// - when server presents its certificate to client, client validates that the SAN in the server's certificate
	// matches the server's service account.
	// - bool ContextImpl::verifySubjectAltName(X509* cert, const std::vector<std::string>& subject_alt_names)
	// verifies the SAN in the certificate.
	if sdsTokenPath, found := node.Metadata[model.NodeMetadataSdsTokenPath]; found && len(sdsTokenPath) > 0 {
		adsLog.Debugf("SDS token path is defined in the proxy metadata")

		// Set the SDS token path in the TLS certificate config
		if c.GetTlsContext() != nil && c.GetTlsContext().GetCommonTlsContext() != nil &&
			c.GetTlsContext().GetCommonTlsContext().GetTlsCertificateSdsSecretConfigs() != nil {
			adsLog.Debugf("***** setSdsTokenPathFromProxyMetadata(), revise SDS_TOKEN_PATH in SDS secret config")
			for _, sc := range c.GetTlsContext().GetCommonTlsContext().GetTlsCertificateSdsSecretConfigs() {
				if sc.GetSdsConfig() != nil && sc.GetSdsConfig().GetApiConfigSource() != nil &&
					sc.GetSdsConfig().GetApiConfigSource().GetGrpcServices() != nil {
					for _, svc := range sc.GetSdsConfig().GetApiConfigSource().GetGrpcServices() {
						// If no call-credential in the cluster, no need to set SDS token path
						if svc.GetGoogleGrpc() != nil && svc.GetGoogleGrpc().GetCallCredentials() != nil &&
							svc.GetGoogleGrpc().GetCredentialsFactoryName() == model.FileBasedMetadataPlugName {
							svc.GetGoogleGrpc().CallCredentials =
								model.ConstructgRPCCallCredentials(sdsTokenPath, model.K8sSAJwtTokenHeaderKey)
						}
					}
				}
			}
		}

		// Set the SDS token path in the TLS validation context
		if c.GetTlsContext() != nil && c.GetTlsContext().GetCommonTlsContext() != nil &&
			c.GetTlsContext().GetCommonTlsContext().GetCombinedValidationContext() != nil &&
			c.GetTlsContext().GetCommonTlsContext().GetCombinedValidationContext().GetValidationContextSdsSecretConfig() != nil {
			sc := c.GetTlsContext().GetCommonTlsContext().GetCombinedValidationContext().GetValidationContextSdsSecretConfig()
			adsLog.Debugf("***** setSdsTokenPathFromProxyMetadata(), revise SDS_TOKEN_PATH in SDS validation context")
			if sc.GetSdsConfig() != nil && sc.GetSdsConfig().GetApiConfigSource() != nil &&
				sc.GetSdsConfig().GetApiConfigSource().GetGrpcServices() != nil {
				for _, svc := range sc.GetSdsConfig().GetApiConfigSource().GetGrpcServices() {
					// If no call-credential in the cluster, no need to set SDS token path
					if svc.GetGoogleGrpc() != nil && svc.GetGoogleGrpc().GetCallCredentials() != nil &&
						svc.GetGoogleGrpc().GetCredentialsFactoryName() == model.FileBasedMetadataPlugName {
						svc.GetGoogleGrpc().CallCredentials =
							model.ConstructgRPCCallCredentials(sdsTokenPath, model.K8sSAJwtTokenHeaderKey)
					}
				}
			}
		}
	}
}
