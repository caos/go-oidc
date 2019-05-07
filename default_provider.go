package oidc

import (
	"context"
	"net/http"
	"strings"

	"golang.org/x/oauth2"

	oidc_http "github.com/caos/go-oidc/http"
)

type DefaultProvider struct {
	endpoints Endpoints

	oauthConfig oauth2.Config
	config      ProviderConfig

	httpClient *http.Client

	verifier Verifier
}

func NewDefaultProvider(providerConfig ProviderConfig, providerOptions ...ProviderOptionFunc) (Provider, error) {
	p := &DefaultProvider{
		config:     providerConfig,
		httpClient: oidc_http.DefaultHTTPClient,
	}

	for _, optionFunc := range providerOptions {
		optionFunc(p)
	}

	if err := p.discover(); err != nil {
		return nil, err
	}

	return p, nil
}

const idTokenKey = "id_token"

func (p *DefaultProvider) CodeExchange(ctx context.Context, code string) (accessToken string, err error) {
	token, err := p.oauthConfig.Exchange(ctx, code)
	if err != nil {
		return "", err //TODO: our error
	}
	idTokenString, ok := token.Extra(idTokenKey).(string)
	if !ok {
		//TODO: implement
	}

	if err := p.verifier.Verify(token.AccessToken, idTokenString); err != nil {
		return "", err //TODO: err
	}

	return token.AccessToken, nil
}

func (p *DefaultProvider) Authorize(ctx context.Context, accessToken string) {
	p.oauthConfig.TokenSource(ctx, &oauth2.Token{AccessToken: accessToken})
}
func (p *DefaultProvider) Userinfo() {}

func WithHTTPClient(client *http.Client) func(o *DefaultProvider) {
	return func(o *DefaultProvider) {
		o.httpClient = client
	}
}

func (p *DefaultProvider) discover() error {
	wellKnown := strings.TrimSuffix(p.config.Issuer, "/") + DiscoveryEndpoint

	oidcConfig := OidcConfiguration{}
	err := oidc_http.Get(wellKnown, &oidcConfig, p.httpClient)
	if err != nil {
		return err
	}

	p.endpoints = oidcConfig.getEndpoints()
	p.oauthConfig = oauth2.Config{
		ClientID:     p.config.ClientID,
		ClientSecret: p.config.ClientSecret,
		Endpoint:     p.endpoints.Endpoint,
		RedirectURL:  p.config.CallbackURL,
		Scopes:       p.config.Scopes,
	}
	return nil
}
