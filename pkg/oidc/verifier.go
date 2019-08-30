package oidc

import "context"

type Verifier interface {
	Verify(ctx context.Context, accessToken, idToken string) error
}
