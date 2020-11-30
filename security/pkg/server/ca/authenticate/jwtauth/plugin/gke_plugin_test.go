package plugin

import (
	"testing"
)

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
