package defaults

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"reflect"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gopkg.in/square/go-jose.v2"

	"github.com/caos/go-oidc/pkg/oidc"
	"github.com/caos/go-oidc/pkg/oidc/mock"
)

func createTestVerifier(confOpts ...ConfFunc) *Verifier {
	return NewVerifier("https://issuer.test/", "test_id", nil, confOpts...).(*Verifier)
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
		// {"Err not set", time.Time{}, ErrExpInvalid(now.Add(-1 * time.Minute))},
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
		opts     ConfFunc
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
		config *verifierConfig
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
		{"OK", fields{&verifierConfig{iat: &iatConfig{}}}, args{time.Now().UTC().Add(-5 * time.Minute)}, false},
		{"OK Ignored", fields{&verifierConfig{iat: &iatConfig{ignore: true}}}, args{time.Now().UTC().Add(5 * time.Minute)}, false},
		{"OK Offset", fields{&verifierConfig{iat: &iatConfig{offset: time.Duration(3 * time.Second)}}}, args{time.Now().UTC().Add(1 * time.Second)}, false},
		{"OK MaxAge", fields{&verifierConfig{iat: &iatConfig{maxAge: time.Duration(6 * time.Minute)}}}, args{time.Now().UTC().Add(-5 * time.Minute)}, false},
		{"Err in future", fields{&verifierConfig{iat: &iatConfig{}}}, args{time.Now().UTC().Add(1 * time.Minute)}, true},
		{"Err in future with offset", fields{&verifierConfig{iat: &iatConfig{offset: time.Duration(3 * time.Second)}}}, args{time.Now().UTC().Add(10 * time.Second)}, true},
		{"Err to old with maxage", fields{&verifierConfig{iat: &iatConfig{maxAge: time.Duration(3 * time.Minute)}}}, args{time.Now().UTC().Add(-5 * time.Minute)}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := &Verifier{
				config: tt.fields.config,
			}
			if err := v.checkIssuedAt(tt.args.issuedAt); (err != nil) != tt.wantErr {
				t.Errorf("verifier.checkIssuedAt() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestDefaultVerifier_checkNonce(t *testing.T) {
	type fields struct {
		config *verifierConfig
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
		{"OK none", fields{&verifierConfig{}}, args{""}, false},
		{"OK nonce", fields{&verifierConfig{nonce: "nonce"}}, args{"nonce"}, false},
		{"OK not checked", fields{&verifierConfig{nonce: ""}}, args{"nonce"}, false},
		{"Err none", fields{&verifierConfig{nonce: "nonce"}}, args{""}, true},
		{"Err wrong", fields{&verifierConfig{nonce: "nonce"}}, args{"nonsense"}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := &Verifier{
				config: tt.fields.config,
			}
			if err := v.checkNonce(tt.args.nonce); (err != nil) != tt.wantErr {
				t.Errorf("verifier.checkNonce() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestDefaultVerifier_checkAuthorizationContextClassReference(t *testing.T) {
	type fields struct {
		config *verifierConfig
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
		{"OK none", fields{&verifierConfig{}}, args{""}, false},
		{"OK with verifier", fields{&verifierConfig{acr: DefaultACRVerifier([]string{"acr1", "acr2"})}}, args{"acr1"}, false},
		{"Err invalid", fields{&verifierConfig{acr: DefaultACRVerifier([]string{"acr1"})}}, args{"acr2"}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := &Verifier{
				config: tt.fields.config,
			}
			if err := v.checkAuthorizationContextClassReference(tt.args.acr); (err != nil) != tt.wantErr {
				t.Errorf("verifier.checkAuthorizationContextClassReference() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestDefaultVerifier_checkAuthTime(t *testing.T) {
	type fields struct {
		config *verifierConfig
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
		{"OK not present", fields{&verifierConfig{}}, args{}, false},
		{"OK not checked", fields{&verifierConfig{}}, args{time.Now().UTC().Add(-1 * time.Minute)}, false},
		{"OK checked", fields{&verifierConfig{maxAge: time.Duration(5 * time.Minute)}}, args{time.Now().UTC().Add(-3 * time.Minute)}, false},
		{"Err not present", fields{&verifierConfig{maxAge: time.Duration(1 * time.Minute)}}, args{}, true},
		{"Err to old", fields{&verifierConfig{maxAge: time.Duration(1 * time.Minute)}}, args{time.Now().UTC().Add(-3 * time.Minute)}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := &Verifier{
				config: tt.fields.config,
			}
			if err := v.checkAuthTime(tt.args.authTime); (err != nil) != tt.wantErr {
				t.Errorf("verifier.checkAuthTime() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// func TestVerifier_checkSignatures(t *testing.T) {
// 	token := `{
// 		"sub": "3",
// 		"aud": [
// 		  "ADMIN",
// 		  "AUTH-V1",
// 		  "IDENTITY-V1",
// 		  "PERMISSION-V1",
// 		  "US-BKD-V1"
// 		],
// 		"exp": 1566451287,
// 		"iat": 1566364887,
// 		"iss": "https://accounts.abraxas.ch/",
// 		"auth_time": 1566307917,
// 		"nonce": "pUZCSHYYysZ2sz4lEV1wf4ojG7wtnQXWODNpK7Zh",
// 		"acr": "0",
// 		"amr": [
// 		  "secureconnect"
// 		],
// 		"at_hash": "-yLws3j9x99IcEd_NZMjZQ",
// 		"azp": "ADMIN",
// 		"preferred_username": "LA102",
// 		"name": "Livio Amstutz",
// 		"family_name": "Amstutz",
// 		"given_name": "Livio",
// 		"locale": "de",
// 		"email": "livio.a@gmail.com",
// 		"email_verified": true
// 	  }`
// 	type fields struct {
// 		config *verifierConfig
// 		keySet oidc.KeySet
// 	}
// 	type args struct {
// 		ctx           context.Context
// 		idTokenString string
// 		payload       []byte
// 	}
// 	tests := []struct {
// 		name    string
// 		fields  fields
// 		args    args
// 		wantErr bool
// 	}{
// 		{"test", fields{config: &verifierConfig{}, keySet: mock.NewKeySet(t)}, args{
// 			context.Background(),
// 			"eyJhbGciOiJSUzI1NiIsImtpZCI6IjI2MzExNzA4MjA2Nzk5MzgzMiJ9.eyJzdWIiOiIzIiwiYXVkIjpbIkFETUlOIiwiQVVUSC1WMSIsIklERU5USVRZLVYxIiwiUEVSTUlTU0lPTi1WMSIsIlVTLUJLRC1WMSJdLCJleHAiOjE1NjY0NTEyODcsImlhdCI6MTU2NjM2NDg4NywiaXNzIjoiaHR0cHM6Ly9hY2NvdW50cy5hYnJheGFzLmNoLyIsImF1dGhfdGltZSI6MTU2NjMwNzkxNywibm9uY2UiOiJwVVpDU0hZWXlzWjJzejRsRVYxd2Y0b2pHN3d0blFYV09ETnBLN1poIiwiYWNyIjoiMCIsImFtciI6WyJzZWN1cmVjb25uZWN0Il0sImF0X2hhc2giOiIteUx3czNqOXg5OUljRWRfTlpNalpRIiwiYXpwIjoiQURNSU4iLCJwcmVmZXJyZWRfdXNlcm5hbWUiOiJMQTEwMiIsIm5hbWUiOiJMaXZpbyBBbXN0dXR6IiwiZmFtaWx5X25hbWUiOiJBbXN0dXR6IiwiZ2l2ZW5fbmFtZSI6IkxpdmlvIiwibG9jYWxlIjoiZGUiLCJlbWFpbCI6ImxpdmlvLmFAZ21haWwuY29tIiwiZW1haWxfdmVyaWZpZWQiOnRydWV9.I_WU0pfwBgGLhIr6h5jHPZNQ3vkvrVX1580P7EAOh0eLPb1mPxC60PNc9s_FT2x_HMfaPeS0W_drePZRsh38XJxC0Y7Q4t88CXFRFFnM5qUtU0igkMORXhDMgO2yX3-oAF1Trkvgz5h7jhEqMuA51uUucy1R95kFaAXXdyjIA1XvREni0jdVq1uaPcWDCOqJvncojVCsx5fmEJX7gO-Dyybr_J4dmImNazzKlC7iCk_SnXxSg5ScisDB3YYxa25YLGXrOhyHxayMpOyVs1ZjpEo4N40lntHcGaiqLYSFo6T3gokt-tF1_9FIqtWVt2lj9qYz5AdD_X6CMf9uHF0w3g",
// 			[]byte(token)}, true},
// 	}
// 	for _, tt := range tests {
// 		t.Run(tt.name, func(t *testing.T) {
// 			v := &Verifier{
// 				config: tt.fields.config,
// 				keySet: tt.fields.keySet,
// 			}
// 			mock.ExpectValid(v.keySet)
// 			if err := v.checkSignature(tt.args.ctx, tt.args.idTokenString, tt.args.payload); (err != nil) != tt.wantErr {
// 				t.Errorf("Verifier.checkSignature() error = %v, wantErr %v", err, tt.wantErr)
// 			}
// 		})
// 	}
// }

func TestVerifier_checkSignature(t *testing.T) {
	// var token string
	// var payload []byte
	type fields struct {
		config *verifierConfig
		keySet oidc.KeySet
	}
	type args struct {
		ctx           context.Context
		idTokenString string
		payload       []byte
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    jose.SignatureAlgorithm
		wantErr bool
	}{
		// TODO: Add test cases.
		{"parsing failure", fields{config: &verifierConfig{}}, args{nil, "", nil}, "", true},
		//{"no signature", fields{config: &verifierConfig{}}, args{nil, newRSAKey(t).signMulti(t, []byte("test")), payload}, "", false},
		//{"multiple signatures", fields{config: &verifierConfig{}}, args{nil, newRSAKey(t).signMulti(t, []byte("test")), payload}, "", false},

		{"unsupported algorithm", fields{config: &verifierConfig{}, keySet: mock.NewKeySetValid(t)}, args{nil, newECDSAKey(t).Sign(t, []byte("test")), []byte("test")}, "", true},
		{"signature invalid", fields{config: &verifierConfig{}, keySet: mock.NewKeySetInValid(t)}, args{nil, NewRSAKey(t).Sign(t, []byte("test")), []byte{}}, "", true},
		{"payload invalid", fields{config: &verifierConfig{}, keySet: mock.NewKeySetValid(t)}, args{nil, NewRSAKey(t).Sign(t, []byte("test")), []byte("wrong")}, "", true},
		{"ok", fields{config: &verifierConfig{}, keySet: mock.NewKeySetValid(t)}, args{nil, NewRSAKey(t).Sign(t, []byte("test")), []byte("test")}, jose.RS256, false},
		{"ok custom signing algorithm", fields{config: &verifierConfig{supportedSignAlgs: []string{"ES256"}}, keySet: mock.NewKeySetValid(t)}, args{nil, newECDSAKey(t).Sign(t, []byte("test")), []byte("test")}, jose.ES256, false},
		//ok
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := &Verifier{
				config: tt.fields.config,
				keySet: tt.fields.keySet,
			}
			got, err := v.checkSignature(tt.args.ctx, tt.args.idTokenString, tt.args.payload)
			if (err != nil) != tt.wantErr {
				t.Errorf("Verifier.checkSignature() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Verifier.checkSignature() = %v, want %v", got, tt.want)
			}
		})
	}
}

type signingKey struct {
	keyID string // optional
	priv  interface{}
	pub   interface{}
	alg   jose.SignatureAlgorithm
}

// sign creates a JWS using the private key from the provided payload.
func (s *signingKey) Sign(t *testing.T, payload []byte) string {
	privKey := &jose.JSONWebKey{Key: s.priv, Algorithm: string(s.alg), KeyID: s.keyID}

	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: s.alg, Key: privKey}, nil)
	if err != nil {
		t.Fatal(err)
	}
	jws, err := signer.Sign(payload)
	if err != nil {
		t.Fatal(err)
	}

	data, err := jws.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// jwk returns the public part of the signing key.
func (s *signingKey) jwk() jose.JSONWebKey {
	return jose.JSONWebKey{Key: s.pub, Use: "sig", Algorithm: string(s.alg), KeyID: s.keyID}
}

func NewRSAKey(t *testing.T) *signingKey {
	priv, err := rsa.GenerateKey(rand.Reader, 1028)
	if err != nil {
		t.Fatal(err)
	}
	return &signingKey{"", priv, priv.Public(), jose.RS256}
}

func newECDSAKey(t *testing.T) *signingKey {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &signingKey{"", priv, priv.Public(), jose.ES256}
}
