package defaults

import (
	"context"
	"net/http"
	"strings"

	"github.com/caos/go-oidc/pkg/oidc/utils"

	"golang.org/x/oauth2"

	oidc_http "github.com/caos/go-oidc/http"
	"github.com/caos/go-oidc/pkg/oidc"
)

type DefaultProvider struct {
	endpoints oidc.Endpoints

	oauthConfig oauth2.Config
	config      oidc.ProviderConfig

	httpClient *http.Client

	verifier       oidc.Verifier
	verifierConfig []ConfFunc
}

func NewDefaultProvider(providerConfig oidc.ProviderConfig, providerOptions ...oidc.ProviderOptionFunc) (oidc.Provider, error) {
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

	if p.verifier == nil {
		p.verifier = NewVerifier(providerConfig.Issuer, providerConfig.ClientID, utils.NewRemoteKeySet(p.httpClient, p.endpoints.JKWsURL), p.verifierConfig...) //TODO: keys endpoint
	}

	return p, nil
}

func WithVerifierConfig(verifierConf ...ConfFunc) oidc.ProviderOptionFunc {
	return oidc.ProviderOptionFunc(func(p oidc.Provider) {
		prov, ok := p.(*DefaultProvider)
		if ok {
			prov.verifierConfig = verifierConf
		}
	})
}

const idTokenKey = "id_token"

func (p *DefaultProvider) AuthURL(state string) string {
	return p.oauthConfig.AuthCodeURL(state)
}

func (p *DefaultProvider) CodeExchange(ctx context.Context, code string) (tokens *oidc.Tokens, err error) {
	token, err := p.oauthConfig.Exchange(ctx, code)
	if err != nil {
		return nil, err //TODO: our error
	}
	idTokenString, ok := token.Extra(idTokenKey).(string)
	if !ok {
		//TODO: implement
	}

	idToken, err := p.verifier.Verify(ctx, token.AccessToken, idTokenString)
	if err != nil {
		return nil, err //TODO: err
	}

	return &oidc.Tokens{Token: token, IDTokenClaims: idToken}, nil
}

func (p *DefaultProvider) Authorize(ctx context.Context, accessToken string) {
	p.oauthConfig.TokenSource(ctx, &oauth2.Token{AccessToken: accessToken})
}
func (p *DefaultProvider) Userinfo() {}

func (p *DefaultProvider) TokenExchange(ctx context.Context, request oidc.TokenExchangeRequest) (newToken *oauth2.Token, err error) {
	// p.oauthConfig.Endpoint.TokenURL
	return nil, nil
}

func (p *DefaultProvider) DelegationTokenExchange(ctx context.Context, subjectToken string, reqOpts ...DelReqOpts) (newToken *oauth2.Token, err error) {
	delRequest := NewDelegationTokenRequest(subjectToken, reqOpts...)
	return p.TokenExchange(ctx, delRequest)
}

func WithHTTPClient(client *http.Client) func(o *DefaultProvider) {
	return func(o *DefaultProvider) {
		o.httpClient = client
	}
}

func (p *DefaultProvider) discover() error {
	wellKnown := strings.TrimSuffix(p.config.Issuer, "/") + oidc.DiscoveryEndpoint

	oidcConfig := oidc.OidcConfiguration{}
	err := oidc_http.Get(wellKnown, &oidcConfig, p.httpClient)
	if err != nil {
		return err
	}

	p.endpoints = oidcConfig.GetEndpoints()
	p.oauthConfig = oauth2.Config{
		ClientID:     p.config.ClientID,
		ClientSecret: p.config.ClientSecret,
		Endpoint:     p.endpoints.Endpoint,
		RedirectURL:  p.config.CallbackURL,
		Scopes:       p.config.Scopes,
	}
	return nil
}
