package oidc

type Verifier interface {
	Verify(accessToken, idToken string) error
}
