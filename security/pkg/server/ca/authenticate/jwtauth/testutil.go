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
	"gopkg.in/square/go-jose.v2"
)

func GenerateJWT(key *jose.JSONWebKey, claims []byte) (string, error) {
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.SignatureAlgorithm(key.Algorithm),
		Key: key}, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create a signer: %v", err)
	}
	signature, err := signer.Sign(claims)
	if err != nil {
		return "", fmt.Errorf("failed to sign claims: %v", err)
	}
	jwt, err := signature.CompactSerialize()
	if err != nil {
		return "", fmt.Errorf("failed to serialize the JWT: %v", err)
	}
	return jwt, nil
}

type jwtSignatureVerifier struct {
	key *jose.JSONWebKey
}

func (j *jwtSignatureVerifier) VerifySignature(ctx context.Context, jwt string) ([]byte, error) {
	sign, err := jose.ParseSigned(jwt)
	if err != nil {
		return nil, fmt.Errorf("failed to parse the JWT: %v", err)
	}
	return sign.Verify(j.key)
}

func GenerateIDToken(key *jose.JSONWebKey, issuer, claims string) (*oidc.IDToken, error) {
	jwt, err := GenerateJWT(key, []byte(claims))
	if err != nil {
		return nil, err
	}
	pubKey := key.Public()
	verifySig := &jwtSignatureVerifier{key: &pubKey}
	verifier := oidc.NewVerifier(issuer, verifySig, &oidc.Config{SkipClientIDCheck: true})
	return verifier.Verify(context.Background(), jwt)
}
