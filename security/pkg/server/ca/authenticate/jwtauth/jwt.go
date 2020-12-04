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

package jwtauth

import (
	"context"
	"fmt"

	"github.com/coreos/go-oidc"
	"istio.io/istio/security/pkg/server/ca/authenticate"
	"istio.io/istio/security/pkg/server/ca/authenticate/jwtauth/plugin"
	"istio.io/pkg/env"
)

var (
	jwksURL = env.RegisterStringVar("ISTIOD_JWT_JWKS_URI", "",
		"The URL of JSON Web Key Set (JWKS) used for istiod JWT authentication").Get()
	issuerURL = env.RegisterStringVar("ISTIOD_JWT_ISSUER_URI", "",
		"The URL of the istiod JWT issuer").Get()
	jwtAudience = env.RegisterStringVar("ISTIOD_JWT_AUDIENCE", "",
		"The JWT audience required by the istiod JWT authentication. A single audience can be specified.").Get()
)

const (
	GenericJwtAuthenticatorType = "GenericJwtAuthenticator"
	GkeJwtType                  = "GKE_JWT"
)

// GenericJwtAuthenticator is different from JwtAuthenticator
// under security/pkg/server/ca/authenticate/oidc.go in the following aspects:
// - oidc.go only supports JWT issued by k8s API server with subject HasPrefix(sa.Sub, "system:serviceaccount").
// - GenericJwtAuthenticator supports extracting JWT claims from JWT of different
//   formats through its plugin mechanism.
// - security/pkg/server/ca/authenticate/oidc.go uses OIDC discovery to get the json web key set.
//   whereas GenericJwtAuthenticator uses the URL of public key server to fetch public key, which
//   works for the server that does not support OIDC discovery, e.g., google service account public key.
// - JwtAuthenticator in security/pkg/server/ca/authenticate/oidc.go is only used at CA
//   and does not have unit tests.
type GenericJwtAuthenticator struct {
	jwtType string
}

var _ authenticate.Authenticator = &GenericJwtAuthenticator{}

// NewGenericJWTAuthenticator creates a new GenericJwtAuthenticator.
func NewGenericJWTAuthenticator(jwtType string) (*GenericJwtAuthenticator, error) {
	if jwtType == GkeJwtType {
		return &GenericJwtAuthenticator{jwtType: jwtType}, nil
	} else {
		return nil, fmt.Errorf("unsupported JWT authenticator type: %v", jwtType)
	}
}

// Authenticate authenticates the JWT.
func (g GenericJwtAuthenticator) Authenticate(ctx context.Context) (*authenticate.Caller, error) {
	var p plugin.JwtPlugin
	if g.jwtType == GkeJwtType {
		p = plugin.NewGkeJwtPlugin()
	} else {
		return nil, fmt.Errorf("unsupported JWT authenticator type: %v", g.jwtType)
	}

	bearerToken, err := authenticate.ExtractBearerToken(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to extract bearer token: %v", err)
	}
	keySet := oidc.NewRemoteKeySet(ctx, jwksURL)
	verifier := oidc.NewVerifier(issuerURL, keySet, &oidc.Config{ClientID: jwtAudience})
	token, err := verifier.Verify(context.Background(), bearerToken)
	if err != nil {
		return nil, fmt.Errorf("failed to verify the token: %v", err)
	}
	err = p.ExtractClaims(token)
	if err != nil {
		return nil, fmt.Errorf("failed to extract claims: %v", err)
	}

	// TODO:
	// - In tests:
	//   -- Follow ~/go/src/github.com/coreos/go-oidc/jwks_test.go to
	//   create a mocked jwks server that returns the public key for validating JWT.
	//   -- Follow ~/go/src/github.com/coreos/go-oidc/verify_test.go to
	//   test authenticating JWTs with invalid issuer, invalid audience, and invalid trust domain.
	//   ~$ go test -v -run TestVerify github.com/coreos/go-oidc/...

	// - Verify that the trust domain in the JWT is the same as the trust domain
	//   of istiod. --> can be virtualized and implemented in plugin.
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
		Identities: []string{fmt.Sprintf(authenticate.IdentityTemplate, p.GetTrustDomain(),
			p.GetNamespace(), p.GetServiceAccount())},
	}, nil
}

func (g GenericJwtAuthenticator) AuthenticatorType() string {
	return GenericJwtAuthenticatorType
}
