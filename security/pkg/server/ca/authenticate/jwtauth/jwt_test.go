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
	"testing"
)

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
			_, err := NewGenericJWTAuthenticator(tt.jwtType, "jwks_url", "issuer", "audience")
			gotErr := err != nil
			if gotErr != tt.expectErr {
				t.Errorf("expect error is %v while actual error is %v", tt.expectErr, gotErr)
			}
		})
	}
}
