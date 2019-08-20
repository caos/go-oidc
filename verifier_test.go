package oidc

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func createTestVerifier(confOpts ...confFunc) *DefaultVerifier {
	return NewDefaultVerifier("https://issuer.test/", "test_id", confOpts...).(*DefaultVerifier)
}

func Test_IDToken_Valid_OK(t *testing.T) {

}

func Test_CheckIssuer(t *testing.T) {
	var issuerTests = []struct {
		issuer   string
		expected error
	}{
		{"https://issuer.test/", nil},
		{"https://issuer.test", ErrIssuerInvalid("https://issuer.test/", "https://issuer.test")},
	}

	verifier := createTestVerifier()

	for _, tt := range issuerTests {
		actual := verifier.checkIssuer(tt.issuer)

		require.Equal(t, tt.expected, actual)
	}
}

func Test_CheckAudience(t *testing.T) {
	var audienceTests = []struct {
		name      string
		audiences []string
		expected  error
	}{
		{"OK single audience", []string{"test_id"}, nil},
		{"OK multiple audiences", []string{"test_id", "test_id2"}, nil},
		{"Err single wrong audience", []string{"test_id2"}, ErrAudienceMissingClientID("test_id")},
	}

	verifier := createTestVerifier()

	for _, tt := range audienceTests {
		actual := verifier.checkAudience(tt.audiences)

		require.Equal(t, tt.expected, actual)
	}
}

func Test_CheckAuthorizedParty(t *testing.T) {
	var authorizedPartyTests = []struct {
		name            string
		audiences       []string
		authorizedParty string
		expected        error
	}{
		{"OK single audience", []string{"test_id"}, "test_id", nil},
		{"OK single audience no azp", []string{"test_id"}, "", nil},
		{"OK multiple audience", []string{"test_id", "aud_2"}, "test_id", nil},
		{"Err multiple audience no azp", []string{"test_id", "aud_2"}, "", ErrAzpMissing()},
		{"Err single audience wrong azp", []string{"test_id"}, "aud_2", ErrAzpInvalid("aud_2", "test_id")},
		{"Err multiple audience wrong azp", []string{"test_id", "aud_2"}, "aud_2", ErrAzpInvalid("aud_2", "test_id")},
	}

	verifier := createTestVerifier()

	for _, tt := range authorizedPartyTests {
		t.Run(tt.name, func(t *testing.T) {
			actual := verifier.checkAuthorizedParty(tt.audiences, tt.authorizedParty)

			require.Equal(t, tt.expected, actual)
		})
	}
}

//TODO: signature

func Test_CheckExpiration_OK(t *testing.T) {
	now := time.Now().UTC().Round(time.Second)
	var expirationTests = []struct {
		name       string
		expiration time.Time
		expected   error
	}{
		{"OK", now.Add(1 * time.Minute), nil},
		{"Err expired", now.Add(-1 * time.Minute), ErrExpInvalid(now.Add(-1 * time.Minute))},
	}

	verifier := createTestVerifier()

	for _, tt := range expirationTests {
		t.Run(tt.name, func(t *testing.T) {
			actual := verifier.checkExpiration(tt.expiration)

			require.Equal(t, tt.expected, actual)
		})
	}
}

func Test_CheckIssuedAt(t *testing.T) {
	now := time.Now().UTC().Round(time.Second)
	var issuedAtTests = []struct {
		name     string
		issuedAt time.Time
		opts     confFunc
		expected error
	}{
		// {"OK", now.Add(-5 * time.Minute), nil, nil},
		{"OK Ignored", now.Add(5 * time.Minute), WithIgnoreIssuedAt(), nil},
		{"OK Offset", now.Add(1 * time.Second), WithIssuedAtOffset(time.Duration(3 * time.Second)), nil},
		{"OK MaxAge", now.Add(-5 * time.Minute), WithIssuedAtMaxAge(time.Duration(6 * time.Minute)), nil},
		{"Err in future", now.Add(1 * time.Minute), nil, ErrIatInFuture(now.Add(1*time.Minute), now)},
		{"Err in future with offset", now.Add(10 * time.Second), WithIssuedAtOffset(time.Duration(3 * time.Second)), ErrIatInFuture(now.Add(10*time.Second), now.Add(3*time.Second))},
		{"Err to old with maxage", now.Add(-5 * time.Minute), WithIssuedAtMaxAge(time.Duration(3 * time.Minute)), ErrIatToOld(now.Add(-3*time.Minute), now.Add(-5*time.Minute))},
	}

	for _, tt := range issuedAtTests {
		t.Run(tt.name, func(t *testing.T) {
			verifier := createTestVerifier(tt.opts)

			actual := verifier.checkIssuedAt(tt.issuedAt)

			require.Equal(t, tt.expected, actual)
		})
	}
}

func TestDefaultVerifier_checkIssuedAt(t *testing.T) {
	type fields struct {
		config *VerifierConfig
	}
	type args struct {
		issuedAt time.Time
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		{"OK", fields{&VerifierConfig{IAT: &IATConfig{}}}, args{time.Now().UTC().Add(-5 * time.Minute)}, false},
		{"OK Ignored", fields{&VerifierConfig{IAT: &IATConfig{Ignore: true}}}, args{time.Now().UTC().Add(5 * time.Minute)}, false},
		{"OK Offset", fields{&VerifierConfig{IAT: &IATConfig{Offset: time.Duration(3 * time.Second)}}}, args{time.Now().UTC().Add(1 * time.Second)}, false},
		{"OK MaxAge", fields{&VerifierConfig{IAT: &IATConfig{MaxAge: time.Duration(6 * time.Minute)}}}, args{time.Now().UTC().Add(-5 * time.Minute)}, false},
		{"Err in future", fields{&VerifierConfig{IAT: &IATConfig{}}}, args{time.Now().UTC().Add(1 * time.Minute)}, true},
		{"Err in future with offset", fields{&VerifierConfig{IAT: &IATConfig{Offset: time.Duration(3 * time.Second)}}}, args{time.Now().UTC().Add(10 * time.Second)}, true},
		{"Err to old with maxage", fields{&VerifierConfig{IAT: &IATConfig{MaxAge: time.Duration(3 * time.Minute)}}}, args{time.Now().UTC().Add(-5 * time.Minute)}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := &DefaultVerifier{
				config: tt.fields.config,
			}
			if err := v.checkIssuedAt(tt.args.issuedAt); (err != nil) != tt.wantErr {
				t.Errorf("DefaultVerifier.checkIssuedAt() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestDefaultVerifier_checkNonce(t *testing.T) {
	type fields struct {
		config *VerifierConfig
	}
	type args struct {
		nonce string
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		{"OK none", fields{&VerifierConfig{}}, args{""}, false},
		{"OK nonce", fields{&VerifierConfig{Nonce: "nonce"}}, args{"nonce"}, false},
		{"OK not checked", fields{&VerifierConfig{Nonce: ""}}, args{"nonce"}, false},
		{"Err none", fields{&VerifierConfig{Nonce: "nonce"}}, args{""}, true},
		{"Err wrong", fields{&VerifierConfig{Nonce: "nonce"}}, args{"nonsense"}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := &DefaultVerifier{
				config: tt.fields.config,
			}
			if err := v.checkNonce(tt.args.nonce); (err != nil) != tt.wantErr {
				t.Errorf("DefaultVerifier.checkNonce() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestDefaultVerifier_checkAuthorizationContextClassReference(t *testing.T) {
	type fields struct {
		config *VerifierConfig
	}
	type args struct {
		acr string
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		{"OK none", fields{&VerifierConfig{}}, args{""}, false},
		{"OK with verifier", fields{&VerifierConfig{ACR: DefaultACRVerifier([]string{"acr1", "acr2"})}}, args{"acr1"}, false},
		{"Err invalid", fields{&VerifierConfig{ACR: DefaultACRVerifier([]string{"acr1"})}}, args{"acr2"}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := &DefaultVerifier{
				config: tt.fields.config,
			}
			if err := v.checkAuthorizationContextClassReference(tt.args.acr); (err != nil) != tt.wantErr {
				t.Errorf("DefaultVerifier.checkAuthorizationContextClassReference() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestDefaultVerifier_checkAuthTime(t *testing.T) {
	type fields struct {
		config *VerifierConfig
	}
	type args struct {
		authTime time.Time
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		{"OK not present", fields{&VerifierConfig{}}, args{}, false},
		{"OK not checked", fields{&VerifierConfig{}}, args{time.Now().UTC().Add(-1 * time.Minute)}, false},
		{"OK checked", fields{&VerifierConfig{MaxAge: time.Duration(5 * time.Minute)}}, args{time.Now().UTC().Add(-3 * time.Minute)}, false},
		{"Err not present", fields{&VerifierConfig{MaxAge: time.Duration(1 * time.Minute)}}, args{}, true},
		{"Err to old", fields{&VerifierConfig{MaxAge: time.Duration(1 * time.Minute)}}, args{time.Now().UTC().Add(-3 * time.Minute)}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := &DefaultVerifier{
				config: tt.fields.config,
			}
			if err := v.checkAuthTime(tt.args.authTime); (err != nil) != tt.wantErr {
				t.Errorf("DefaultVerifier.checkAuthTime() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
