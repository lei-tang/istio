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
)

type JwtPlugin interface {
	// GetIssuer returns issuer claim.
	GetIssuer() string

	// GetAudience returns the audience claim.
	GetAudience() []string

	// GetServiceAccount() returns the service account claim.
	GetServiceAccount() string

	// GetNamespace() returns the namespace claim.
	GetNamespace() string

	// GetTrustDomain returns the trust domain claim.
	GetTrustDomain() string

	// Authenticate returns nil if the authentication succeeds.
	// Otherwise, returns the error.
	Authenticate(ctx context.Context) error
}
