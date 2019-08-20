package oidc

import (
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"hash"
	"strings"
	"time"

	"gopkg.in/square/go-jose.v2"

	str_utils "github.com/caos/utils/strings"
)

func NewDefaultVerifier(issuer, clientID string, confOpts ...confFunc) Verifier {
	conf := &verifierConfig{
		issuer:   issuer,
		clientID: clientID,
		iat:      &iatConfig{},
	}

	for _, opt := range confOpts {
		if opt != nil {
			opt(conf)
		}
	}
	return &DefaultVerifier{config: conf}
}

type DefaultVerifier struct {
	config *verifierConfig
}

type confFunc func(*verifierConfig)

func WithIgnoreIssuedAt() func(*verifierConfig) {
	return func(conf *verifierConfig) {
		conf.iat.ignore = true
	}
}

func WithIssuedAtOffset(offset time.Duration) func(*verifierConfig) {
	return func(conf *verifierConfig) {
		conf.iat.offset = offset
	}
}

func WithIssuedAtMaxAge(maxAge time.Duration) func(*verifierConfig) {
	return func(conf *verifierConfig) {
		conf.iat.maxAge = maxAge
	}
}

func WithNonce(nonce string) func(*verifierConfig) {
	return func(conf *verifierConfig) {
		conf.nonce = nonce
	}
}

func WithACRVerifier(verifier ACRVerifier) func(*verifierConfig) {
	return func(conf *verifierConfig) {
		conf.acr = verifier
	}
}

func WithAuthTimeMaxAge(maxAge time.Duration) func(*verifierConfig) {
	return func(conf *verifierConfig) {
		conf.maxAge = maxAge
	}
}

type verifierConfig struct {
	issuer   string
	clientID string
	nonce    string
	iat      *iatConfig
	acr      ACRVerifier
	maxAge   time.Duration
	now      time.Time
}

type iatConfig struct {
	ignore bool
	offset time.Duration
	maxAge time.Duration
}

type ACRVerifier func(string) error

func DefaultACRVerifier(possibleValues []string) func(string) error {
	return func(acr string) error {
		if !str_utils.Contains(possibleValues, acr) {
			return ErrAcrInvalid(possibleValues, acr)
		}
		return nil
	}
}

func (v *DefaultVerifier) Verify(accessToken, idToken string) error {
	v.config.now = time.Now().UTC()
	return nil
}

func (v *DefaultVerifier) now() time.Time {
	if v.config.now.IsZero() {
		v.config.now = time.Now().UTC().Round(time.Second)
	}
	return v.config.now
}

func (v *DefaultVerifier) verifyIDToken(idTokenString string) error {
	//1. if encrypted --> decrypt
	decrypted, err := v.decryptToken(idTokenString)
	if err != nil {
		return err
	}
	claims, err := v.parseToken(decrypted)
	if err != nil {
		return err
	}
	// token, err := jwt.ParseWithClaims(decrypted, claims, func(token *jwt.Token) (interface{}, error) {
	//2, check issuer (exact match)
	if err := v.checkIssuer(claims.Issuer); err != nil {
		return err
	}

	//3. check aud (aud must contain client_id, all aud strings must be allowed)
	if err = v.checkAudience(claims.Audiences); err != nil {
		return err
	}

	if err = v.checkAuthorizedParty(claims.Audiences, claims.AuthorizedParty); err != nil {
		return err
	}

	//6. check signature by keys
	//7. check alg default is rs256
	//8. check if alg is mac based (hs...) -> audience contains client_id. for validation use utf-8 representation of your client_secret
	if err = v.checkSignature(claims); err != nil {
		return err
	}

	//9. check exp before now
	if err = v.checkExpiration(claims.Expiration); err != nil {
		return err
	}

	//10. check iat duration is optional (can be checked)
	if err = v.checkIssuedAt(claims.IssuedAt); err != nil {
		return err
	}

	//11. check nonce (check if optional possible) id_token.nonce == sentNonce
	if err = v.checkNonce(claims.Nonce); err != nil {
		return err
	}

	//12. if acr requested check acr
	if err = v.checkAuthorizationContextClassReference(claims.AuthenticationContextClassReference); err != nil {
		return err
	}

	//13. if auth_time requested check if auth_time is less than max age
	if err = v.checkAuthTime(claims.AuthTime); err != nil {
		return err
	}
	//return idtoken struct, err

	return nil
	// })
	// _ = token
	// return err
}

func (v *DefaultVerifier) parseToken(tokenString string) (idToken *IDToken, err error) {
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return nil, nil //TODO: err NewValidationError("token contains an invalid number of segments", ValidationErrorMalformed)
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("oidc: malformed jwt payload: %v", err)
	}
	err = json.Unmarshal(payload, idToken)
	return idToken, err
}

func (v *DefaultVerifier) checkIssuer(issuer string) error {
	if v.config.issuer != issuer {
		return ErrIssuerInvalid(v.config.issuer, issuer)
	}
	return nil
}

func (v *DefaultVerifier) checkAudience(audiences []string) error {
	if !str_utils.Contains(audiences, v.config.clientID) {
		return ErrAudienceMissingClientID(v.config.clientID)
	}

	//TODO: check aud trusted
	return nil
}

//4. if multiple aud strings --> check if azp
//5. if azp --> check azp == client_id
func (v *DefaultVerifier) checkAuthorizedParty(audiences []string, authorizedParty string) error {
	if len(audiences) > 1 {
		if authorizedParty == "" {
			return ErrAzpMissing()
		}
	}
	if authorizedParty != "" && authorizedParty != v.config.clientID {
		return ErrAzpInvalid(authorizedParty, v.config.clientID)
	}
	return nil
}

func (v *DefaultVerifier) checkSignature(claims *IDToken) error {
	return nil
}

func (v *DefaultVerifier) checkExpiration(expiration time.Time) error {
	expiration = expiration.Round(time.Second)
	if !v.now().Before(expiration) {
		return ErrExpInvalid(expiration)
	}
	return nil
}

func (v *DefaultVerifier) checkIssuedAt(issuedAt time.Time) error {
	if v.config.iat.ignore {
		return nil
	}
	issuedAt = issuedAt.Round(time.Second)
	offset := v.now().Add(v.config.iat.offset).Round(time.Second)
	if issuedAt.After(offset) {
		return ErrIatInFuture(issuedAt, offset)
	}
	if v.config.iat.maxAge == 0 {
		return nil
	}
	maxAge := v.now().Add(-v.config.iat.maxAge).Round(time.Second)
	if issuedAt.Before(maxAge) {
		return ErrIatToOld(maxAge, issuedAt)
	}
	return nil
}
func (v *DefaultVerifier) checkNonce(nonce string) error {
	if v.config.nonce == "" {
		return nil
	}
	if v.config.nonce != nonce {
		return ErrNonceInvalid(v.config.nonce, nonce)
	}
	return nil
}
func (v *DefaultVerifier) checkAuthorizationContextClassReference(acr string) error {
	if v.config.acr != nil {
		return v.config.acr(acr)
	}
	return nil
}
func (v *DefaultVerifier) checkAuthTime(authTime time.Time) error {
	if v.config.maxAge == 0 {
		return nil
	}
	if authTime.IsZero() {
		return ErrAuthTimeNotPresent()
	}
	authTime = authTime.Round(time.Second)
	maxAge := v.now().Add(-v.config.maxAge).Round(time.Second)
	if authTime.Before(maxAge) {
		return ErrAuthTimeToOld(maxAge, authTime)
	}
	return nil
}

func (v *DefaultVerifier) decryptToken(tokenString string) (string, error) {
	return tokenString, nil //TODO: impl
}

// func (v *DefaultVerifier) parseIDToken(tokenString string) (IDToken, error) {
// 	var claims jwt.StandardClaims
// 	token, err := jwt.ParseWithClaims(tokenString, &claims, func(token *jwt.Token) (interface{}, error) {
// 		claims.VerifyIssuer(v.config.Issuer, true)

// 		// return token.Header["alg"]
// 	})

// 	payload, err := parseJWT(rawIDToken)
// 	if err != nil {
// 		return nil, fmt.Errorf("oidc: malformed jwt: %v", err)
// 	}
// 	var token IDToken
// 	if err := json.Unmarshal(payload, &token); err != nil {
// 		return nil, fmt.Errorf("oidc: failed to unmarshal claims: %v", err)
// 	}
// 	return token, nil //TODO: impl
// }

func (v *DefaultVerifier) verifyAccessToken(accessToken, atHash string, sigAlgorithm jose.SignatureAlgorithm) error {
	if atHash == "" {
		return nil //TODO: return error
	}

	tokenHash, err := getHashAlgorithm(sigAlgorithm)
	if err != nil {
		return err
	}

	tokenHash.Write([]byte(accessToken)) // hash documents that Write will never return an error
	sum := tokenHash.Sum(nil)[:tokenHash.Size()/2]
	actual := base64.RawURLEncoding.EncodeToString(sum)
	if actual != atHash {
		return nil //TODO: error
	}
	return nil
}

func getHashAlgorithm(sigAlgorithm jose.SignatureAlgorithm) (hash.Hash, error) {
	switch sigAlgorithm {
	case jose.RS256, jose.ES256, jose.PS256:
		return sha256.New(), nil
	case jose.RS384, jose.ES384, jose.PS384:
		return sha512.New384(), nil
	case jose.RS512, jose.ES512, jose.PS512:
		return sha512.New(), nil
	default:
		return nil, fmt.Errorf("oidc: unsupported signing algorithm %q", sigAlgorithm)
	}
}
