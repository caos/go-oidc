package defaults

import (
	"github.com/caos/go-oidc/pkg/oidc"
)

//DelegationTokenRequest is an implementation of TokenExchangeRequest
//it exchanges a "urn:ietf:params:oauth:token-type:access_token" with an optional
//"urn:ietf:params:oauth:token-type:access_token" actor token for a
//"urn:ietf:params:oauth:token-type:access_token" delegation token
func DelegationTokenRequest(subjectToken string, opts ...oidc.TokenExchangeOption) *oidc.TokenExchangeRequest {
	return oidc.NewTokenExchangeRequest(subjectToken, oidc.AccessTokenType, opts...)
}
