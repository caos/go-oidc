package defaults

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"

	"github.com/gorilla/schema"

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
	req, err := formRequest(p.endpoints.TokenURL, request)
	if err != nil {
		return nil, err
	}
	auth := base64.StdEncoding.EncodeToString([]byte(p.config.ClientID + ":" + p.config.ClientSecret))
	req.Header.Set("Authorization", "Basic "+auth)
	token := new(oauth2.Token)
	if err := httpRequest(p.httpClient, req, token); err != nil {
		return nil, err
	}
	return token, nil
}

func formRequest(endpoint string, request interface{}) (*http.Request, error) {
	form := make(map[string][]string)
	encoder := schema.NewEncoder()
	if err := encoder.Encode(request, form); err != nil {
		return nil, err
	}
	body := strings.NewReader(url.Values(form).Encode())
	req, err := http.NewRequest("POST", endpoint, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return req, nil
}

func httpRequest(client *http.Client, req *http.Request, response interface{}) error {
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("unable to read response body: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("http status not ok: %s %s", resp.Status, body)
	}

	err = json.Unmarshal(body, response)
	if err != nil {
		return fmt.Errorf("failed to unmarshal response: %v %s", err, body)
	}
	return nil
}

func (p *DefaultProvider) DelegationTokenExchange(ctx context.Context, subjectToken string, reqOpts ...oidc.TokenExchangeOption) (newToken *oauth2.Token, err error) {
	return p.TokenExchange(ctx, DelegationTokenRequest(subjectToken, reqOpts...))
}

func (p *DefaultProvider) ObTokenExchange(ctx context.Context, subjectToken string, resource string) (newToken *oauth2.Token, err error) {
	return p.TokenExchange(ctx, ObTokenRequest(subjectToken, resource))
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
