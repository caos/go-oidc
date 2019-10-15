package oidc

import (
	"context"
	"net/http"
	"time"

	"golang.org/x/oauth2"
)

//Provider declares the minimal interface for oidc clients
type Provider interface {

	//AuthURL returns the authorization endpoint with a given state
	AuthURL(state string) string

	//AuthURLHandler should implement the AuthURL func as http.HandlerFunc
	//(redirecting to the auth endpoint)
	AuthURLHandler(state string) http.HandlerFunc

	//CodeExchange implements the OIDC Token Request (oauth2 Authorization Code Grant)
	//returning an `Access Token` and `ID Token Claims`
	CodeExchange(ctx context.Context, code string) (*Tokens, error)

	//CodeExchangeHandler extends the CodeExchange func,
	//calling the provided callback func on success with additional returned `state`
	CodeExchangeHandler(callback func(http.ResponseWriter, *http.Request, *Tokens, string)) http.HandlerFunc

	//ClientCredentials implements the oauth2 Client Credentials Grant
	//requesting an `Access Token` for the client itself, without user context
	ClientCredentials(ctx context.Context, scopes ...string) (*oauth2.Token, error)

	//Introspects calls the Introspect Endpoint
	//for validating an (access) token
	Introspect(ctx context.Context, token string) (TokenIntrospectResponse, error)

	//Userinfo implements the OIDC Userinfo call
	//returning the info of the user for the requested scopes of an access token
	Userinfo()

	// Authorize(ctx context.Context, accessToken string) //TODO: ???
}

//ProviderExtension extends the `Provider` interface with the oauth2 `Password Grant`
//
//This interface is separated from the standard `Provider` interface as the `password grant`
//is part of the oauth2 and therefore OIDC specification, but should only be used when there's no
//other possibility, so IMHO never ever. Ever.
type ProviderExtension interface {
	Provider

	//PasswordGrant implements the oauth2 `Password Grant`,
	//requesting an access token with the users `username` and `password`
	PasswordGrant(context.Context, string, string) (*oauth2.Token, error)
}

// type TokenExchangeRequest interface {
// 	SubjectToken() string
// 	SubjectTokenType() string
// 	ActorToken() string
// 	ActorTokenType() string
// 	Resource() []url.URL //TODO: uri
// 	Audience() []string
// 	Scope() []string
// 	RequestedTokenType() string

// 	MarschalForm() url.Values
// }

type TokenIntrospectResponse interface {
	Active() bool
	Scope() string
	ClientID() string
	Username() string
	TokenType() string //TODO: typed?
	Expiration() time.Time
	IssuedAt() time.Time
	NotBefore() time.Time
	Subject() string
	Audience() []string
	Issuer() string
	JWTID() string
}

type ProviderConfig struct {
	ClientID     string
	ClientSecret string
	CallbackURL  string
	Issuer       string
	Scopes       []string
}

type ProviderOptionFunc func(Provider)

type Endpoints struct {
	oauth2.Endpoint
	IntrospectURL string
	UserinfoURL   string
	JKWsURL       string
}
