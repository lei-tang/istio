// Copyright 2020 Istio Authors
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

// GenericJwtAuthenticator is different from JwtAuthenticator
// under security/pkg/server/ca/authenticate/oidc.go in the following aspects:
// - GenericJwtAuthenticator supports extracting JWT claims from JWT of different
//   formats through its plugin mechanism.
// - GenericJwtAuthenticator authenticates issuer and audience based on the user configuration.
// - JwtAuthenticator in security/pkg/server/ca/authenticate/oidc.go is only used at CA
//   and does not have unit tests.
package jwtauth

import (
	"context"
	"fmt"

	"github.com/coreos/go-oidc"
	"istio.io/istio/security/pkg/server/ca/authenticate"
	"istio.io/istio/security/pkg/server/ca/authenticate/jwtauth/plugin"
	"istio.io/pkg/env"
)

const (
	GenericJwtAuthenticatorType = "GenericJwtAuthenticator"
	GkeJwtType = "GoogleKubernetesEngine"
)

var (
	jwtType = env.RegisterStringVar("JWT_TYPE", GkeJwtType,
		"The type of JWT to authenticate. The default type is GoogleKubernetesEngine").Get()
)

type JwtExtractor interface {
	// GetIssuer returns issuer claim.
	GetIssuer() string

	// GetAudience returns audience claim.
	GetAudience() []string

	// GetServiceAccount() returns service account claim.
	GetServiceAccount() string

	// GetNamespace() returns namespace claim.
	GetNamespace() string

	// GetTrustDomain returns trust domain claim.
	GetTrustDomain() string
}

type GenericJwtAuthenticator struct {
	provider *oidc.Provider
	verifier *oidc.IDTokenVerifier
}

var _ authenticate.Authenticator = &GenericJwtAuthenticator{}

// NewGenericJWTAuthenticator creates a new GenericJwtAuthenticator.
func NewGenericJWTAuthenticator(iss string, audience string) (*GenericJwtAuthenticator, error) {
	provider, err := oidc.NewProvider(context.Background(), iss)
	if err != nil {
		return nil, fmt.Errorf("running in cluster with K8S tokens, but failed to initialize %s %s", iss, err)
	}

	return &GenericJwtAuthenticator{
		provider: provider,
		verifier: provider.Verifier(&oidc.Config{ClientID: audience}),
	}, nil
}

// Authenticate - based on the old OIDC authenticator for mesh expansion.
func (j *GenericJwtAuthenticator) Authenticate(ctx context.Context) (*authenticate.Caller, error) {
	bearerToken, err := authenticate.ExtractBearerToken(ctx)
	if err != nil {
		return nil, fmt.Errorf("ID token extraction error: %v", err)
	}

	idToken, err := j.verifier.Verify(context.Background(), bearerToken)
	if err != nil {
		return nil, fmt.Errorf("failed to verify the ID token (error %v)", err)
	}

	var extractor JwtExtractor
	if jwtType == GkeJwtType {
		extractor, err = plugin.NewGkeJwtExtractor(idToken)
		if err != nil {
			return nil, fmt.Errorf("failed at NewGkeJwtExtractor (error %v)", err)
		}
	} else {
		return nil, fmt.Errorf("unsupported JWT type: %v", jwtType)
	}

	// TODO:
	// - https://b.corp.google.com/issues/171316378 to pass in public key url.
	// - Verify that the audience and issuer in the JWT are as expected as those in
	//   the environmental variables.
	// - Verify that the trust domain in the JWT is the same as the trust domain
	//   of istiod.
	//   This verification ensures that a client with a JWT in trust domain foo
	//   can only access an istiod in the same trust domin.
	//   Expected trust domain: istiod trust domain is from mesh config.
	//   Actual trust domain: the trust domain claim in the JWT.
	//   Trust domain is from sub claim in https://b.corp.google.com/issues/171317150
	// - No change of code on istiod checkConnectionIdentity(), which validates the
	//   service account and namespace in the spiffe id extracted matches those in the
	//   proxy node metadata. Proxy node metadata are from the ISTIO_META_* env variables
	//   defined on proxy when the proxy is deployed and included in the connection to
	//   from proxy to istiod.
	// - GenericJwtAuthenticator should be created and used in istiod. If configured to
	//   use GenericJwtAuthenticator, it should be the only authenticator. Otherwise,
	//   even if GenericJwtAuthenticator rejects a connection, other authenticators may
	//   allow the connection.
	//   The identities allowed are extracted in:
	//   func (s *DiscoveryServer) authenticate(ctx context.Context) ([]string, error) {}
	//   The authenticators used by XDS are configured in:
	//   if features.XDSAuth {
	//	    s.XDSServer.Authenticators = authenticators
	//   }
	//   A new environmental variable should be added to istiod to specify GenericJwtAuthenticator
	//   as the only authenticator for s.XDSServer.Authenticators.
	return &authenticate.Caller{
		AuthSource: authenticate.AuthSourceIDToken,
		Identities: []string{fmt.Sprintf(authenticate.IdentityTemplate, extractor.GetTrustDomain(),
			extractor.GetNamespace(), extractor.GetServiceAccount())},
	}, nil
}

func (j GenericJwtAuthenticator) AuthenticatorType() string {
	return GenericJwtAuthenticatorType
}
