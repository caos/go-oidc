package defaults

import (
	"context"
	"encoding/base64"
	"net/http"
	"strings"

	"golang.org/x/oauth2"

	oidc_http "github.com/caos/go-oidc/http"
	"github.com/caos/go-oidc/pkg/oidc"
	"github.com/caos/go-oidc/pkg/oidc/utils"
)

const (
	idTokenKey = "id_token"
	stateParam = "state"
)

type DefaultProvider struct {
	endpoints oidc.Endpoints

	oauthConfig oauth2.Config
	config      *oidc.ProviderConfig

	httpClient    *http.Client
	cookieHandler *utils.CookieHandler

	verifier oidc.Verifier
}

func NewDefaultProvider(providerConfig *oidc.ProviderConfig, providerOptions ...DefaultProviderOpts) (oidc.ProviderDelegationTokenExchange, error) {
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
		p.verifier = NewVerifier(providerConfig.Issuer, providerConfig.ClientID, utils.NewRemoteKeySet(p.httpClient, p.endpoints.JKWsURL)) //TODO: keys endpoint
	}

	return p, nil
}

type DefaultProviderOpts func(p *DefaultProvider)

func WithCookieHandler(cookieHandler *utils.CookieHandler) DefaultProviderOpts {
	return func(p *DefaultProvider) {
		p.cookieHandler = cookieHandler
	}
}

func WithHTTPClient(client *http.Client) DefaultProviderOpts {
	return func(p *DefaultProvider) {
		p.httpClient = client
	}
}

func (p *DefaultProvider) AuthURL(state string) string {
	return p.oauthConfig.AuthCodeURL(state)
}

func (p *DefaultProvider) AuthURLHandler(state string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := p.trySetStateCookie(w, state); err != nil {
			http.Error(w, "failed to create state cookie: "+err.Error(), http.StatusUnauthorized)
			return
		}
		http.Redirect(w, r, p.AuthURL(state), http.StatusFound)
	}
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

func (p *DefaultProvider) CodeExchangeHandler(callback func(http.ResponseWriter, *http.Request, *oidc.Tokens, string)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		state, err := p.tryReadStateCookie(w, r)
		if err != nil {
			http.Error(w, "failed to get state: "+err.Error(), http.StatusUnauthorized)
			return
		}
		tokens, err := p.CodeExchange(r.Context(), r.URL.Query().Get("code"))
		if err != nil {
			http.Error(w, "failed to exchange token: "+err.Error(), http.StatusUnauthorized)
			return
		}
		callback(w, r, tokens, state)
	}
}

func (p *DefaultProvider) Introspect(ctx context.Context, accessToken string) (oidc.TokenIntrospectResponse, error) {
	// req := &http.Request{}
	// resp, err := p.httpClient.Do(req)
	// if err != nil {

	// }
	// p.endpoints.IntrospectURL
	return nil, nil
}

func (p *DefaultProvider) Authorize(ctx context.Context, accessToken string) {
	p.oauthConfig.TokenSource(ctx, &oauth2.Token{AccessToken: accessToken})
}
func (p *DefaultProvider) Userinfo() {}

func (p *DefaultProvider) TokenExchange(ctx context.Context, request *oidc.TokenExchangeRequest) (newToken *oauth2.Token, err error) {
	return p.callTokenEndpoint(request)
}

func (p *DefaultProvider) callTokenEndpoint(request interface{}) (newToken *oauth2.Token, err error) {
	req, err := utils.FormRequest(p.endpoints.TokenURL, request)
	if err != nil {
		return nil, err
	}
	auth := base64.StdEncoding.EncodeToString([]byte(p.config.ClientID + ":" + p.config.ClientSecret))
	req.Header.Set("Authorization", "Basic "+auth)
	token := new(oauth2.Token)
	if err := utils.HttpRequest(p.httpClient, req, token); err != nil {
		return nil, err
	}
	return token, nil
}

func (p *DefaultProvider) ClientCredentials(ctx context.Context, scopes ...string) (newToken *oauth2.Token, err error) {
	return p.callTokenEndpoint(oidc.ClientCredentialsGrantBasic(scopes...))
}

func (p *DefaultProvider) DelegationTokenExchange(ctx context.Context, subjectToken string, reqOpts ...oidc.TokenExchangeOption) (newToken *oauth2.Token, err error) {
	return p.TokenExchange(ctx, DelegationTokenRequest(subjectToken, reqOpts...))
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

func (p *DefaultProvider) trySetStateCookie(w http.ResponseWriter, state string) error {
	if p.cookieHandler != nil {
		if err := p.cookieHandler.SetQueryCookie(w, stateParam, state); err != nil {
			return err
		}
	}
	return nil
}

func (p *DefaultProvider) tryReadStateCookie(w http.ResponseWriter, r *http.Request) (state string, err error) {
	if p.cookieHandler == nil {
		return r.FormValue(stateParam), nil
	}
	state, err = p.cookieHandler.CheckQueryCookie(r, stateParam)
	if err != nil {
		return "", err
	}
	p.cookieHandler.DeleteCookie(w, stateParam)
	return state, nil
}
