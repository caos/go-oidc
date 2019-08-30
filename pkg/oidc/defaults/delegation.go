package defaults

import "net/url"

const (
	accessTokenType     = "urn:ietf:params:oauth:token-type:access_token"
	refreshTokenType    = "urn:ietf:params:oauth:token-type:refresh_token"
	idTokenType         = "urn:ietf:params:oauth:token-type:id_token"
	jwtTokenType        = "urn:ietf:params:oauth:token-type:jwt"
	delegationTokenType = accessTokenType
)

//DelegationTokenRequest is an implementation of TokenExchangeRequest
//it exchanges a "urn:ietf:params:oauth:token-type:access_token" with an optional
//"urn:ietf:params:oauth:token-type:access_token" actor token for a
//"urn:ietf:params:oauth:token-type:access_token" delegation token
type DelegationTokenRequest struct {
	subjectToken string
	actorToken   string
	resource     []url.URL //TODO: uri
	audience     []string
	scope        []string
}

type DelReqOpts func(*DelegationTokenRequest)

func WithActorToken(token string) func(*DelegationTokenRequest) {
	return func(req *DelegationTokenRequest) {
		req.actorToken = token
	}
}

func WithAudience(audience []string) func(*DelegationTokenRequest) {
	return func(req *DelegationTokenRequest) {
		req.audience = audience
	}
}

func WithResource(resource []url.URL) func(*DelegationTokenRequest) {
	return func(req *DelegationTokenRequest) {
		req.resource = resource
	}
}

func WithScope(scope []string) func(*DelegationTokenRequest) {
	return func(req *DelegationTokenRequest) {
		req.scope = scope
	}
}

func NewDelegationTokenRequest(subjectToken string, reqOpts ...DelReqOpts) *DelegationTokenRequest {
	req := &DelegationTokenRequest{
		subjectToken: subjectToken,
	}
	for _, opt := range reqOpts {
		opt(req)
	}
	return req
}

func (t *DelegationTokenRequest) ActorToken() string {
	return t.actorToken
}
func (t *DelegationTokenRequest) ActorTokenType() string {
	return accessTokenType
}
func (t *DelegationTokenRequest) Audience() []string {
	return t.audience
}
func (t *DelegationTokenRequest) RequestedTokenType() string {
	return delegationTokenType
}
func (t *DelegationTokenRequest) Resource() []url.URL {
	return t.resource
}
func (t *DelegationTokenRequest) Scope() []string {
	return t.scope
}
func (t *DelegationTokenRequest) SubjectToken() string {
	return t.subjectToken
}
func (t *DelegationTokenRequest) SubjectTokenType() string {
	return accessTokenType
}
