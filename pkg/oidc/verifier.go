package oidc

import (
	"context"
)

type Verifier interface {
	Verify(ctx context.Context, accessToken, idTokenString string) (*IDToken, error)
}
