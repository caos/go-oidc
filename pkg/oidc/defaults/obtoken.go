package defaults

import (
	"github.com/caos/go-oidc/pkg/oidc"
)

//ObTokenRequest is an Abraxas implementation of DelegationTokenRequest (TokenExchangeRequest)
//it exchanges a "urn:ietf:params:oauth:token-type:access_token" with an optional
//"urn:ietf:params:oauth:token-type:access_token" actor token for a
//"urn:ietf:params:oauth:token-type:access_token" delegation token
func ObTokenRequest(subjectToken string, resource string) *oidc.TokenExchangeRequest {
	return oidc.NewTokenExchangeRequest(subjectToken, oidc.AccessTokenType, oidc.WithGrantType("urn:abraxas:iam:grant_type:ob_token"), oidc.WithAudience([]string{resource}))
}
