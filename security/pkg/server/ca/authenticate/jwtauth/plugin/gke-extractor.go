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
	"fmt"

	oidc "github.com/coreos/go-oidc"
	"istio.io/istio/security/pkg/server/ca/authenticate/jwtauth"
)

type GkeJwtExtractor struct {
	issuer string
	audience []string
	serviceAccount string
	nameSpace string
	trustDomain string
	token *oidc.IDToken
}

type GkeJwtPayload struct {
	Iss string `json:"iss"`
	Sub string `json:"sub"`
	Aud []string `json:"aud"`
	Exp int `json:"exp"`
	Namespace string `json:"namespace"`
	Serviceaccount string `json:"serviceaccount"`
}

func NewGkeJwtExtractor(idt *oidc.IDToken) (jwtauth.JwtExtractor, error) {
	extractor := &GkeJwtExtractor{
		token: idt,
	}
	p := &GkeJwtPayload{}
	if err := idt.Claims(p); err != nil {
		return nil, fmt.Errorf("failed to extract claims from ID token: %v", err)
	}
	extractor.issuer = p.Iss
	extractor.nameSpace = p.Namespace
	extractor.serviceAccount = p.Serviceaccount
	extractor.audience = p.Aud
	extractor.trustDomain = p.Sub
	return extractor, nil
}

// GetIssuer returns issuer claim.
func (p *GkeJwtExtractor) GetIssuer() string {
	return p.issuer
}

// GetAudience returns audience claim.
func (p *GkeJwtExtractor) GetAudience() []string {
	return p.audience
}

// GetServiceAccount() returns service account claim.
func (p *GkeJwtExtractor) GetServiceAccount() string {
	return p.serviceAccount
}

// GetNamespace() returns namespace claim.
func (p *GkeJwtExtractor) GetNamespace() string {
	return p.nameSpace
}

// GetTrustDomain returns trust domain claim.
func (p *GkeJwtExtractor) GetTrustDomain() string {
	return p.trustDomain
}
