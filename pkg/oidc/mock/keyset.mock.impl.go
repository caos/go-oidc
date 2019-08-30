package mock

import (
	context "context"
	"errors"
	"testing"

	"gopkg.in/square/go-jose.v2"

	"github.com/golang/mock/gomock"

	"github.com/caos/go-oidc/pkg/oidc"
)

func NewKeySet(t *testing.T) oidc.KeySet {
	ks := NewMockKeySet(gomock.NewController(t))
	return ks
}

func NewKeySetValid(t *testing.T) oidc.KeySet {
	ks := NewKeySet(t)
	ExpectValid(ks)
	return ks
}

func NewKeySetInValid(t *testing.T) oidc.KeySet {
	ks := NewKeySet(t)
	ExpectInValid(ks)
	return ks
}

func ExpectValid(ks oidc.KeySet) {
	mockKS := ks.(*MockKeySet)
	mockKS.EXPECT().VerifySignature(gomock.Any(), gomock.Any()).DoAndReturn(
		func(ctx context.Context, jws *jose.JSONWebSignature) ([]byte, error) {
			return jws.UnsafePayloadWithoutVerification(), nil
		})
}

func ExpectInValid(ks oidc.KeySet) {
	mockKS := ks.(*MockKeySet)
	mockKS.EXPECT().VerifySignature(gomock.Any(), gomock.Any()).Return([]byte{}, errors.New("invalid signature"))
}
