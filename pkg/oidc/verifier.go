package oidc

import (
	"context"
)

//Verifier implement the Token Response Validation as defined in OIDC specification
//https://openid.net/specs/openid-connect-core-1_0.html#TokenResponseValidation
type Verifier interface {

	//Verify checks the access_token and id_token and returns the `id token claims`
	Verify(ctx context.Context, accessToken, idTokenString string) (*IDTokenClaims, error)
}
