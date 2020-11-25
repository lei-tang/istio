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

package plugin

import (
	"context"
	"fmt"

	oidc "github.com/coreos/go-oidc"
	"istio.io/istio/pkg/spiffe"
	"istio.io/istio/security/pkg/server/ca/authenticate"
	"istio.io/istio/security/pkg/server/ca/authenticate/jwtauth"
	"istio.io/pkg/env"
)

var (
	jwksURL = env.RegisterStringVar("JWKS_URL", "",
		"The URL of JSON Web Key Set (JWKS) used for JWT authentication").Get()
	issuerURL = env.RegisterStringVar("ISSUER_URL", "",
		"The URL of the JWT issuer").Get()
	jwtAudience = env.RegisterStringVar("JWT_AUDIENCE", "",
		"The JWT audience required by the JWT authentication").Get()
)

type GkeJwtPlugin struct {
	issuer         string
	audience       []string
	serviceAccount string
	nameSpace      string
	trustDomain    string
}

// GkeJwtPayload defines the claims to extract from the JWT
type GkeJwtPayload struct {
	Iss            string   `json:"iss"`
	Sub            string   `json:"sub"`
	Aud            []string `json:"aud"`
	Exp            int      `json:"exp"`
	Namespace      string   `json:"namespace"`
	Serviceaccount string   `json:"serviceaccount"`
}

func NewGkeJwtPlugin() (jwtauth.JwtPlugin, error) {
	return &GkeJwtPlugin{}, nil
}

// GetIssuer returns issuer claim.
func (g *GkeJwtPlugin) GetIssuer() string {
	return g.issuer
}

// GetAudience returns audience claim.
func (g *GkeJwtPlugin) GetAudience() []string {
	return g.audience
}

// GetServiceAccount() returns service account claim.
func (g *GkeJwtPlugin) GetServiceAccount() string {
	return g.serviceAccount
}

// GetNamespace() returns namespace claim.
func (g *GkeJwtPlugin) GetNamespace() string {
	return g.nameSpace
}

// GetTrustDomain returns trust domain claim.
func (g *GkeJwtPlugin) GetTrustDomain() string {
	return g.trustDomain
}

// Authenticate returns whether the JWT passes the authentication or not.
func (g *GkeJwtPlugin) Authenticate(ctx context.Context) error {
	keySet := oidc.NewRemoteKeySet(ctx, jwksURL)
	verifier := oidc.NewVerifier(issuerURL, keySet, &oidc.Config{ClientID: jwtAudience})

	bearerToken, err := authenticate.ExtractBearerToken(ctx)
	if err != nil {
		return fmt.Errorf("failed to extract bearer token: %v", err)
	}
	token, err := verifier.Verify(context.Background(), bearerToken)
	if err != nil {
		return fmt.Errorf("failed to verify the token: %v", err)
	}

	p := &GkeJwtPayload{}
	if err := token.Claims(p); err != nil {
		return fmt.Errorf("failed to extract claims from the token: %v", err)
	}
	if p.Sub != spiffe.GetTrustDomain() {
		return fmt.Errorf("the trust domain (%v) in the JWT does not match the required trust domain (%v)",
			p.Sub, spiffe.GetTrustDomain())
	}

	g.issuer = p.Iss
	g.nameSpace = p.Namespace
	g.serviceAccount = p.Serviceaccount
	g.audience = p.Aud
	g.trustDomain = p.Sub
	return nil
}
