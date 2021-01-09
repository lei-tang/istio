// Copyright Istio Authors
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

package caclient

import (
	"context"
	"fmt"
	"io/ioutil"
	"strings"

	"google.golang.org/grpc/credentials"

	"istio.io/istio/pkg/security"
	"istio.io/pkg/log"
)

// TokenProvider is a grpc PerRPCCredentials that can be used to attach a JWT token to each gRPC call.
// TokenProvider can be used for both XDS and CA connection, which may involve token exchange through STS.
type TokenProvider struct {
	opts security.Options
	// TokenProvider can be used for both XDS and CA connection. Because CA is often used with
	// external systems and XDS is not often (yet?), many of the security options only apply to CA
	// communication. A more proper solution would be to have separate options for CA and XDS, but
	// this requires API changes.
	forCA bool
}

var _ credentials.PerRPCCredentials = &TokenProvider{}

// TODO add metrics
// TODO change package
func NewCATokenProvider(opts security.Options) *TokenProvider {
	return &TokenProvider{opts, true}
}

func NewXDSTokenProvider(opts security.Options) *TokenProvider {
	return &TokenProvider{opts, false}
}

func (t *TokenProvider) GetRequestMetadata(ctx context.Context, uri ...string) (map[string]string, error) {
	if t == nil {
		return nil, nil
	}
	token, err := t.GetToken()
	if err != nil {
		return nil, err
	}
	if token == "" {
		return nil, nil
	}
	return map[string]string{
		"authorization": "Bearer " + token,
	}, nil
}

// Allow the token provider to be used regardless of transport security; callers can determine whether
// this is safe themselves.
func (t *TokenProvider) RequireTransportSecurity() bool {
	return false
}

// GetToken fetches a token to attach to a request. Returning "", nil will cause no header to be
// added; while a non-nil error will block the request If the token selected is not found, no error
// will be returned, causing no authorization header to be set. This ensures that even if the JWT
// token is missing (for example, on a VM that has rebooted, causing the token to be removed from
// volatile memory), we can still proceed and allow other authentication methods to potentially
// handle the request, such as mTLS.
func (t *TokenProvider) GetToken() (string, error) {
	if !t.forCA && !t.opts.XdsEnableTokenExchange {
		// For XDS flow, when token exchange is disabled, we only support reading from file.
		if t.opts.JWTPath == "" {
			return "", nil
		}
		tok, err := ioutil.ReadFile(t.opts.JWTPath)
		if err != nil {
			log.Warnf("failed to fetch token from file: %v", err)
			return "", nil
		}
		return strings.TrimSpace(string(tok)), nil
	}
	// We have two modes: using the newer CredentialFetcher or just reading directly from file
	var token string
	if t.opts.CredFetcher != nil {
		var err error
		token, err = t.opts.CredFetcher.GetPlatformCredential()
		if err != nil {
			return "", fmt.Errorf("fetch platform credential: %v", err)
		}
	} else {
		if t.opts.JWTPath == "" {
			return "", nil
		}
		tok, err := ioutil.ReadFile(t.opts.JWTPath)
		if err != nil {
			log.Warnf("failed to fetch token from file: %v", err)
			return "", nil
		}
		token = strings.TrimSpace(string(tok))
	}

	// Regardless of where the token came from, we (optionally) can exchange the token for a different
	// one using the configured TokenExchanger.
	return t.exchangeToken(token)
}

// exchangeToken exchanges the provided token using TokenExchanger, if configured. If not, the
// original token is returned.
func (t *TokenProvider) exchangeToken(token string) (string, error) {
	if t.opts.TokenExchanger == nil {
		return token, nil
	}
	return t.opts.TokenExchanger.ExchangeToken(token)
}
