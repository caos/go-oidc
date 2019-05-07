package oidc

import (
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"fmt"
	"hash"

	"gopkg.in/square/go-jose.v2"
)

type Verifier interface {
	Verify(accessToken, idToken string) error
}

func NewDefaultVerifier() Verifier {
	return &DefaultVerifier{}
}

type DefaultVerifier struct {
}

func (v *DefaultVerifier) Verify(accessToken, idToken string) error {

	return nil
}

func (v *DefaultVerifier) verifyIDToken(idTokenString string) error {
	//1. if encrypted --> decrypt

	//2, check issuer (exact match)

	//3. check aud (aud must contain client_id, all aud strings must be allowed)

	//4. if multiple aud strings --> check if azp

	//5. if azp --> check azp == client_id

	//6. check signature by keys

	//7. check alg default is rs256

	//8. check if alg is mac based (hs...) -> audience contains client_id. for validation use utf-8 representation of your client_secret

	//9. check exp before now

	//10. check iat duration is optional (can be checked)

	//11. check nonce (check if optional possible) id_token.nonce == sentNonce

	//12. if acr requested check acr

	//13. if auth_time requested check if auth_time is less than max age

	//return idtoken struct, err
	return nil
}

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
