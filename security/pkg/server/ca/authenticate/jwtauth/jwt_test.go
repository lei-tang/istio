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
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"

	"google.golang.org/grpc/metadata"
	"gopkg.in/square/go-jose.v2"
	"istio.io/istio/security/pkg/server/ca/authenticate"
)

type jwksServer struct {
	key jose.JSONWebKeySet
	t   *testing.T
}

func (k *jwksServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if err := json.NewEncoder(w).Encode(k.key); err != nil {
		k.t.Fatalf("failed to encode the jwks: %v", err)
	}
}

func TestNewGenericJWTAuthenticator(t *testing.T) {
	tests := []struct {
		name      string
		expectErr bool
		jwtType   string
	}{
		{
			name:      "valid jwt type",
			expectErr: false,
			jwtType:   GkeJwtType,
		},
		{
			name:      "invalid jwt type",
			expectErr: true,
			jwtType:   "invalid",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewGenericJWTAuthenticator(tt.jwtType, "jwks_url", "issuer", "audience", "baz")
			gotErr := err != nil
			if gotErr != tt.expectErr {
				t.Errorf("expect error is %v while actual error is %v", tt.expectErr, gotErr)
			}
		})
	}
}

func TestAuthenticate(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 512)
	if err != nil {
		t.Fatalf("failed to generate a private key: %v", err)
	}
	key := jose.JSONWebKey{Algorithm: string(jose.RS256), Key: rsaKey}
	keySet := jose.JSONWebKeySet{}
	keySet.Keys = append(keySet.Keys, key.Public())
	server := httptest.NewServer(&jwksServer{key: keySet})
	defer server.Close()

	expStr := fmt.Sprintf("%d", time.Now().Add(time.Minute).UnixNano())
	// For k8s subject format, the subject should be
	// - "sub": "system:serviceaccount:bar:foo" instead of "sub": "baz.svc.id.goog[bar/foo]"
	//claims := `{"iss": "` + server.URL + `", "aud": ["audience"], "sub": "system:serviceaccount:bar:foo", "exp": ` + expStr + `}`
	claims := `{"iss": "` + server.URL + `", "aud": ["audience"], "sub": "baz.svc.id.goog[bar/foo]", "exp": ` + expStr + `}`
	token, err := GenerateJWT(&key, []byte(claims))

	testCases := map[string]struct {
		token      string
		expectErr  bool
		expectedID string
	}{
		"No bearer token": {
			expectErr: true,
		},
		"Invalid token": {
			token:     "invalid-token",
			expectErr: true,
		},
		"Valid token": {
			token:      token,
			expectErr:  false,
			expectedID: fmt.Sprintf(authenticate.IdentityTemplate, "baz.svc.id.goog", "bar", "foo"),
		},
	}

	for id, tc := range testCases {
		t.Run(id, func(t *testing.T) {
			ctx := context.Background()
			md := metadata.MD{}
			if tc.token != "" {
				token := authenticate.BearerTokenPrefix + tc.token
				md.Append("authorization", token)
			}
			ctx = metadata.NewIncomingContext(ctx, md)

			authenticator, err := NewGenericJWTAuthenticator(GkeJwtType, server.URL, server.URL, "audience", "baz.svc.id.goog")
			if err != nil {
				t.Errorf("failed to create the JWT authenticator: %v", err)
				return
			}
			actualCaller, err := authenticator.Authenticate(ctx)
			gotErr := (err != nil)
			if gotErr != tc.expectErr {
				t.Errorf("gotErr (%v) whereas expectErr (%v)", gotErr, tc.expectErr)
			}
			if gotErr {
				return
			}
			expectedCaller := &authenticate.Caller{
				AuthSource: authenticate.AuthSourceIDToken,
				Identities: []string{tc.expectedID},
			}
			if !reflect.DeepEqual(actualCaller, expectedCaller) {
				t.Errorf("Case %q: Unexpected token: want %v but got %v", id, expectedCaller, actualCaller)
			}
		})
	}
}
