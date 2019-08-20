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

var (
	ErrIssuerInvalid = func(expected, actual string) *validationError {
		return ValidationError("Issuer does not match. Expected: %s, got: %s", expected, actual)
	}
	ErrAudienceMissingClientID = func(clientID string) *validationError {
		return ValidationError("Audience is not valid. Audience must contain client_id (%s)", clientID)
	}
	ErrAzpMissing = func() *validationError {
		return ValidationError("Authorized Party is not set. If Token is valid for multiple audiences, azp must not be empty")
	}
	ErrAzpInvalid = func(azp, clientID string) *validationError {
		return ValidationError("Authorized Party is not valid. azp (%s) must be equal to client_id (%s)", azp, clientID)
	}
	ErrExpInvalid = func(exp time.Time) *validationError {
		return ValidationError("Token has expired %v", exp)
	}
	ErrIatInFuture = func(exp, now time.Time) *validationError {
		return ValidationError("IssuedAt of token is in the future (%v, now with offset: %v)", exp, now)
	}
	ErrIatToOld = func(maxAge, iat time.Time) *validationError {
		return ValidationError("IssuedAt of token must not be older than %v, but was %v (%v to old)", maxAge, iat, maxAge.Sub(iat))
	}
	ErrNonceInvalid = func(expected, actual string) *validationError {
		return ValidationError("Nonce does not match. Expected: %s, got: %s", expected, actual)
	}
	ErrAcrInvalid = func(expected []string, actual string) *validationError {
		return ValidationError("ACR is invalid. Expected one of: %v, got: %s", expected, actual)
	}

	ErrAuthTimeNotPresent = func() *validationError {
		return ValidationError("claim `auth_time` of token is missing")
	}
	ErrAuthTimeToOld = func(maxAge, authTime time.Time) *validationError {
		return ValidationError("Auth Time of token must not be older than %v, but was %v (%v to old)", maxAge, authTime, maxAge.Sub(authTime))
	}
)

type Verifier interface {
	Verify(accessToken, idToken string) error
}

func NewDefaultVerifier(issuer, clientID string, confOpts ...confFunc) Verifier {
	conf := &VerifierConfig{
		Issuer:   issuer,
		ClientID: clientID,
		IAT:      &IATConfig{},
	}

	for _, opt := range confOpts {
		if opt != nil {
			opt(conf)
		}
	}
	return &DefaultVerifier{config: conf}
}

type DefaultVerifier struct {
	config *VerifierConfig
}

type confFunc func(*VerifierConfig)

func WithIgnoreIssuedAt() func(*VerifierConfig) {
	return func(conf *VerifierConfig) {
		conf.IAT.Ignore = true
	}
}

func WithIssuedAtOffset(offset time.Duration) func(*VerifierConfig) {
	return func(conf *VerifierConfig) {
		conf.IAT.Offset = offset
	}
}

func WithIssuedAtMaxAge(maxAge time.Duration) func(*VerifierConfig) {
	return func(conf *VerifierConfig) {
		conf.IAT.MaxAge = maxAge
	}
}

func WithNonce(nonce string) func(*VerifierConfig) {
	return func(conf *VerifierConfig) {
		conf.Nonce = nonce
	}
}

func WithACRVerifier(verifier ACRVerifier) func(*VerifierConfig) {
	return func(conf *VerifierConfig) {
		conf.ACR = verifier
	}
}

func WithAuthTimeMaxAge(maxAge time.Duration) func(*VerifierConfig) {
	return func(conf *VerifierConfig) {
		conf.MaxAge = maxAge
	}
}

type VerifierConfig struct {
	Issuer   string
	ClientID string
	Nonce    string
	IAT      *IATConfig
	ACR      ACRVerifier
	MaxAge   time.Duration
	now      time.Time
}

type IATConfig struct {
	Ignore bool
	Offset time.Duration
	MaxAge time.Duration
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

func ValidationError(message string, args ...interface{}) *validationError {
	return &validationError{fmt.Sprintf(message, args...)} //TODO: impl
}

type validationError struct {
	message string
}

func (v *validationError) Error() string {
	return v.message
}

func (v *DefaultVerifier) checkIssuer(issuer string) error {
	if v.config.Issuer != issuer {
		return ErrIssuerInvalid(v.config.Issuer, issuer)
	}
	return nil
}

func (v *DefaultVerifier) checkAudience(audiences []string) error {
	if !str_utils.Contains(audiences, v.config.ClientID) {
		return ErrAudienceMissingClientID(v.config.ClientID)
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
	if authorizedParty != "" && authorizedParty != v.config.ClientID {
		return ErrAzpInvalid(authorizedParty, v.config.ClientID)
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
	if v.config.IAT.Ignore {
		return nil
	}
	issuedAt = issuedAt.Round(time.Second)
	offset := v.now().Add(v.config.IAT.Offset).Round(time.Second)
	if issuedAt.After(offset) {
		return ErrIatInFuture(issuedAt, offset)
	}
	if v.config.IAT.MaxAge == 0 {
		return nil
	}
	maxAge := v.now().Add(-v.config.IAT.MaxAge).Round(time.Second)
	if issuedAt.Before(maxAge) {
		return ErrIatToOld(maxAge, issuedAt)
	}
	return nil
}
func (v *DefaultVerifier) checkNonce(nonce string) error {
	if v.config.Nonce == "" {
		return nil
	}
	if v.config.Nonce != nonce {
		return ErrNonceInvalid(v.config.Nonce, nonce)
	}
	return nil
}
func (v *DefaultVerifier) checkAuthorizationContextClassReference(acr string) error {
	if v.config.ACR != nil {
		return v.config.ACR(acr)
	}
	return nil
}
func (v *DefaultVerifier) checkAuthTime(authTime time.Time) error {
	if v.config.MaxAge == 0 {
		return nil
	}
	if authTime.IsZero() {
		return ErrAuthTimeNotPresent()
	}
	authTime = authTime.Round(time.Second)
	maxAge := v.now().Add(-v.config.MaxAge).Round(time.Second)
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
