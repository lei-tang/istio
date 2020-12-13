package plugin

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"reflect"
	"testing"
	"time"

	"gopkg.in/square/go-jose.v2"
	"istio.io/istio/security/pkg/server/ca/authenticate/jwtauth"
)

func TestExtractClaims(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 512)
	if err != nil {
		t.Fatalf("failed to generate a private key: %v", err)
	}
	expStr := fmt.Sprintf("%d", time.Now().Add(600*time.Second).UnixNano())
	key := jose.JSONWebKey{Algorithm: string(jose.RS256), Key: rsaKey}
	tests := []struct {
		name      string
		expectErr bool
		issuer    string
		claims    string
	}{
		{
			name:      "valid token",
			expectErr: false,
			issuer:    "http://issuer",
			claims: `{"iss": "http://issuer", "aud": ["audience"], "sub": "baz.svc.id.goog[bar/foo]", "exp": ` +
				expStr + `}`,
		},
		{
			name:      "invalid token (missing subject)",
			expectErr: true,
			issuer:    "http://issuer",
			claims:    `{"iss": "http://issuer", "aud": ["audience"], "exp": ` + expStr + `}`,
		},
		{
			name:      "invalid token (invalid subject)",
			expectErr: true,
			issuer:    "http://issuer",
			claims: `{"iss": "http://issuer", "aud": ["audience"], "sub": "baz.svc.id.googbar/foo]", "exp": ` +
				expStr + `}`,
		},
		{
			name:      "invalid token (invalid issuer)",
			expectErr: true,
			issuer:    "http://issuer",
			claims: `{"iss": "invalid", "aud": ["audience"], "sub": "baz.svc.id.goog[bar/foo]", "exp": ` +
				expStr + `}`,
		},
		{
			name:      "invalid token (missing expiration time)",
			expectErr: true,
			issuer:    "http://issuer",
			claims:    `{"iss": "http://issuer", "aud": ["audience"], "sub": "baz.svc.id.goog[bar/foo]"}`,
		},
		{
			name:      "invalid token (JWT expired)",
			expectErr: true,
			issuer:    "http://issuer",
			claims:    `{"iss": "http://issuer", "aud": ["audience"], "sub": "baz.svc.id.goog[bar/foo]", "exp":12345678}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := NewGkeJwtPlugin()
			token, err := jwtauth.GenerateIDToken(&key, tt.issuer, tt.claims)
			if err != nil {
				if !tt.expectErr {
					t.Errorf("failed to generate an IDToken: %v", err)
				}
				return
			}
			err = p.ExtractClaims(token)
			gotErr := err != nil
			if gotErr != tt.expectErr {
				t.Errorf("expect error is %v while actual error is %v", tt.expectErr, gotErr)
			}
		})
	}
}

func TestGetIssuer(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 512)
	if err != nil {
		t.Fatalf("failed to generate a private key: %v", err)
	}
	expStr := fmt.Sprintf("%d", time.Now().Add(600*time.Second).UnixNano())
	key := jose.JSONWebKey{Algorithm: string(jose.RS256), Key: rsaKey}
	claims := `{"iss": "http://issuer", "aud": ["audience"], "sub": "baz.svc.id.goog[bar/foo]", "exp": ` +
		expStr + `}`
	p := NewGkeJwtPlugin()
	token, err := jwtauth.GenerateIDToken(&key, "http://issuer", claims)
	if err != nil {
		t.Fatalf("failed to generate an IDToken: %v", err)
	}
	err = p.ExtractClaims(token)
	if err != nil {
		t.Fatalf("failed to extract claims %v", err)
	}
	if p.GetIssuer() != "http://issuer" {
		t.Errorf("issuer is not as expected, expect (%v) but got (%v)",
			"http://issuer", p.GetIssuer())
	}
}

func TestGetAudience(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 512)
	if err != nil {
		t.Fatalf("failed to generate a private key: %v", err)
	}
	expStr := fmt.Sprintf("%d", time.Now().Add(600*time.Second).UnixNano())
	key := jose.JSONWebKey{Algorithm: string(jose.RS256), Key: rsaKey}
	claims := `{"iss": "http://issuer", "aud": ["audience"], "sub": "baz.svc.id.goog[bar/foo]", "exp": ` +
		expStr + `}`
	p := NewGkeJwtPlugin()
	token, err := jwtauth.GenerateIDToken(&key, "http://issuer", claims)
	if err != nil {
		t.Fatalf("failed to generate an IDToken: %v", err)
	}
	err = p.ExtractClaims(token)
	if err != nil {
		t.Fatalf("failed to extract claims %v", err)
	}
	if !reflect.DeepEqual(p.GetAudience(), []string{"audience"}) {
		t.Errorf("audience is not as expected, expect (%v) but got (%v)",
			[]string{"audience"}, p.GetAudience())
	}
}

func TestGetServiceAccount(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 512)
	if err != nil {
		t.Fatalf("failed to generate a private key: %v", err)
	}
	expStr := fmt.Sprintf("%d", time.Now().Add(600*time.Second).UnixNano())
	key := jose.JSONWebKey{Algorithm: string(jose.RS256), Key: rsaKey}
	claims := `{"iss": "http://issuer", "aud": ["audience"], "sub": "baz.svc.id.goog[bar/foo]", "exp": ` +
		expStr + `}`
	p := NewGkeJwtPlugin()
	token, err := jwtauth.GenerateIDToken(&key, "http://issuer", claims)
	if err != nil {
		t.Fatalf("failed to generate an IDToken: %v", err)
	}
	err = p.ExtractClaims(token)
	if err != nil {
		t.Fatalf("failed to extract claims %v", err)
	}
	if p.GetServiceAccount() != "foo" {
		t.Errorf("service account is not as expected, expect (%v) but got (%v)",
			"foo", p.GetServiceAccount())
	}
}

func TestGetNamespace(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 512)
	if err != nil {
		t.Fatalf("failed to generate a private key: %v", err)
	}
	expStr := fmt.Sprintf("%d", time.Now().Add(600*time.Second).UnixNano())
	key := jose.JSONWebKey{Algorithm: string(jose.RS256), Key: rsaKey}
	claims := `{"iss": "http://issuer", "aud": ["audience"], "sub": "baz.svc.id.goog[bar/foo]", "exp": ` +
		expStr + `}`
	p := NewGkeJwtPlugin()
	token, err := jwtauth.GenerateIDToken(&key, "http://issuer", claims)
	if err != nil {
		t.Fatalf("failed to generate an IDToken: %v", err)
	}
	err = p.ExtractClaims(token)
	if err != nil {
		t.Fatalf("failed to extract claims %v", err)
	}
	if p.GetNamespace() != "bar" {
		t.Errorf("name space is not as expected, expect (%v) but got (%v)",
			"bar", p.GetNamespace())
	}
}

func TestGetTrustDomain(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 512)
	if err != nil {
		t.Fatalf("failed to generate a private key: %v", err)
	}
	expStr := fmt.Sprintf("%d", time.Now().Add(600*time.Second).UnixNano())
	key := jose.JSONWebKey{Algorithm: string(jose.RS256), Key: rsaKey}
	claims := `{"iss": "http://issuer", "aud": ["audience"], "sub": "baz.svc.id.goog[bar/foo]", "exp": ` +
		expStr + `}`
	p := NewGkeJwtPlugin()
	token, err := jwtauth.GenerateIDToken(&key, "http://issuer", claims)
	if err != nil {
		t.Fatalf("failed to generate an IDToken: %v", err)
	}
	err = p.ExtractClaims(token)
	if err != nil {
		t.Fatalf("failed to extract claims %v", err)
	}
	if p.GetTrustDomain() != "baz.svc.id.goog" {
		t.Errorf("trust domain is not as expected, expect (%v) but got (%v)",
			"baz.svc.id.goog", p.GetTrustDomain())
	}
}

func TestExtractGkeSubjectProperties(t *testing.T) {
	subject := "baz.svc.id.goog[bar/foo]"
	invalidSubject1 := "baz.invalid.goog[bar/foo]"
	invalidSubject2 := "baz.svc.id.googbar/foo]"
	invalidSubject3 := "baz.svc.id.goog[barfoo]"

	tests := []struct {
		name        string
		subject     string
		expectedRet GkeSubjectProperties
		expectErr   bool
	}{
		{
			name:        "subject properties match expected",
			subject:     subject,
			expectedRet: GkeSubjectProperties{Trustdomain: "baz.svc.id.goog", Namespace: "bar", Name: "foo"},
			expectErr:   false,
		},
		{
			name:      "invalid subject case 1",
			subject:   invalidSubject1,
			expectErr: true,
		},
		{
			name:      "invalid subject case 2",
			subject:   invalidSubject2,
			expectErr: true,
		},
		{
			name:      "invalid subject case 3",
			subject:   invalidSubject3,
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			property, err := ExtractGkeSubjectProperties(tt.subject)
			gotErr := err != nil
			if gotErr != tt.expectErr {
				t.Errorf("expect error is %v while actual error is %v", tt.expectErr, gotErr)
			} else {
				if !tt.expectErr && *property != tt.expectedRet {
					t.Errorf("return is unexpected; expect %v but got %v",
						tt.expectedRet, *property)
				}
			}
		})
	}
}
