package defaults

import (
	"github.com/caos/go-oidc/pkg/oidc"
)

//DelegationTokenRequest is an implementation of TokenExchangeRequest
//it exchanges a "urn:ietf:params:oauth:token-type:access_token" with an optional
//"urn:ietf:params:oauth:token-type:access_token" actor token for a
//"urn:ietf:params:oauth:token-type:access_token" delegation token
type obTokenRequest struct {
	*oidc.TokenExchangeRequest
	// subjectToken string    `schema:"subject_token"`
	// actorToken   string    `schema:"actor_token"`
	// resource     []url.URL `schema:"-"` //TODO: uri
	// audience     []string  `schema:"audience"`
	// scope        []string  `schema:"scope"`
}

// type DelReqOpts func(*DelegationTokenRequest)

// func WithActorToken(token string) func(*DelegationTokenRequest) {
// 	return func(req *DelegationTokenRequest) {
// 		req.ActorToken = token
// 	}
// }

// func WithAudience(audience []string) func(*DelegationTokenRequest) {
// 	return func(req *DelegationTokenRequest) {
// 		req.Audience = audience
// 	}
// }

// func WithResource(resource []url.URL) func(*DelegationTokenRequest) {
// 	return func(req *DelegationTokenRequest) {
// 		req.Resource = resource
// 	}
// }

// func WithScope(scope []string) func(*DelegationTokenRequest) {
// 	return func(req *DelegationTokenRequest) {
// 		req.Scope = scope
// 	}
// }

func NewObTokenRequest(subjectToken string, resource []string) *obTokenRequest {
	req := &obTokenRequest{
		oidc.NewTokenExchangeRequest(subjectToken, oidc.AccessTokenType, oidc.WithGrantType("urn:abraxas:iam:grant_type:ob_token"), oidc.WithAudience(resource)),
	}
	return req
}

// func (t *DelegationTokenRequest) ActorToken() string {
// 	return t.TokenExchangeRequestS.ActorToken
// }
// func (t *DelegationTokenRequest) ActorTokenType() string {
// 	return accessTokenType
// }
// func (t *DelegationTokenRequest) Audience() []string {
// 	return t.TokenExchangeRequestS.Audience
// }
// func (t *DelegationTokenRequest) RequestedTokenType() string {
// 	return delegationTokenType
// }
// func (t *DelegationTokenRequest) Resource() []url.URL {
// 	return t.TokenExchangeRequestS.Resource
// }
// func (t *DelegationTokenRequest) Scope() []string {
// 	return t.TokenExchangeRequestS.Scope
// }
// func (t *DelegationTokenRequest) SubjectToken() string {
// 	return t.TokenExchangeRequestS.SubjectToken
// }
// func (t *DelegationTokenRequest) SubjectTokenType() string {
// 	return accessTokenType
// }
