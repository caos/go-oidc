package defaults_test

import (
	"encoding/json"
	"testing"
	"time"

	"gopkg.in/square/go-jose.v2"

	"github.com/stretchr/testify/require"

	"github.com/caos/go-oidc/pkg/oidc"
	"github.com/caos/go-oidc/pkg/oidc/defaults"
	"github.com/caos/go-oidc/pkg/oidc/mock"
)

func TestVerifier_VerifyIDToken(t *testing.T) {
	now := time.Now().UTC().Round(time.Second)
	token := &oidc.IDToken{Audiences: []string{"client_id"}, AuthTime: now.Add(-3 * time.Minute), Expiration: now.Add(1 * time.Minute), IssuedAt: now.Add(-1 * time.Minute), Issuer: "https://issuer"}
	tokenWithSig := func() *oidc.IDToken { t := *token; t.Signature = jose.SignatureAlgorithm("RS256"); return &t }()

	tests := []struct {
		name     string
		verifier oidc.Verifier
		token    *oidc.IDToken
		want     *oidc.IDToken
		wantErr  bool
	}{
		// {"ok", fields{"https://issuer", "client_id", mock.NewKeySetValid(t), []defaults.ConfFunc{defaults.WithSupportedSigningAlgorithms("HS256")}}, args{"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJpc3MiOiJodHRwczovL2lzc3VlciIsImF1ZCI6ImNsaWVudF9pZCJ9.FAnUDzQQPgcnuqh49LXeoLXsexJCZH9zQ0a8AjF4XNc"}, nil, false},
		{"ok", defaults.NewVerifier("https://issuer", "client_id", mock.NewKeySetValid(t)), token, tokenWithSig, false},
		{"Err wrong audience", defaults.NewVerifier("https://issuer", "clientid", mock.NewKeySetValid(t)), token, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// v := defaults.NewVerifier(tt.fields.issuer, tt.fields.clientID, tt.fields.keyset, tt.fields.opts...)
			dv, ok := tt.verifier.(*defaults.Verifier)
			require.True(t, ok)

			idTokenJSON, err := json.Marshal(tt.token)
			require.NoError(t, err)
			idTokenString := defaults.NewRSAKey(t).Sign(t, idTokenJSON)

			got, err := dv.VerifyIDToken(nil, idTokenString)
			if (err != nil) != tt.wantErr {
				t.Errorf("Verifier.VerifyIDToken() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			require.Equal(t, tt.want, got)
		})
	}
}
