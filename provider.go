package oidc

import (
	"net/http"
	"strings"

	"golang.org/x/oauth2"
)

const (
	DiscoveryEndpoint = "/.well-known/openid-configuration"
)

type Endpoints struct {
	oauth2.Endpoint
	IntrospectURL string
	UserinfoURL   string
	jkwsURL       string
}

type Provider struct {
	issuer   string
	endpoint *Endpoints

	httpClient *http.Client
}

type oidcConfiguration struct {
	AuthURL  string
	TokenURL string
}

type OidcConfiguration struct {
	Issuer                            string   `json:"issuer,omitempty"`
	AuthorizationEndpoint             string   `json:"authorization_endpoint,omitempty"`
	TokenEndpoint                     string   `json:"token_endpoint,omitempty"`
	IntrospectionEndpoint             string   `json:"introspection_endpoint,omitempty"`
	UserinfoEndpoint                  string   `json:"userinfo_endpoint,omitempty"`
	EndSessionEndpoint                string   `json:"end_session_endpoint,omitempty"`
	CheckSessionIframe                string   `json:"check_session_iframe,omitempty"`
	JwksUri                           string   `json:"jwks_uri,omitempty"`
	ScopesSupported                   []string `json:"scopes_supported,omitempty"`
	ResponseTypesSupported            []string `json:"response_types_supported,omitempty"`
	ResponseModesSupported            []string `json:"response_modes_supported,omitempty"`
	GrantTypesSupported               []string `json:"grant_types_supported,omitempty"`
	SubjectTypesSupported             []string `json:"subject_types_supported,omitempty"`
	IdTokenSigningAlgValuesSupported  []string `json:"id_token_signing_alg_values_supported,omitempty"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported,omitempty"`
	ClaimsSupported                   []string `json:"claims_supported,omitempty"`
}

func (oidcConf *OidcConfiguration) getEndpoints() *Endpoints {
	return &Endpoints{
		Endpoint: oauth2.Endpoint{
			AuthURL:   oidcConf.AuthorizationEndpoint,
			AuthStyle: oauth2.AuthStyleAutoDetect,
			TokenURL:  oidcConf.TokenEndpoint,
		},
		IntrospectURL: oidcConf.IntrospectionEndpoint,
		UserinfoURL:   oidcConf.UserinfoEndpoint,
		jkwsURL:       oidcConf.JwksUri,
	}
}

type providerOptionFunc func(*Provider)

func WithHTTPClient(client *http.Client) func(p *Provider) {
	return func(p *Provider) {
		p.httpClient = client
	}
}

func NewProvider(issuer string, providerOptions ...providerOptionFunc) (*Provider, error) {
	p := &Provider{
		issuer:     issuer,
		httpClient: DefaultHTTPClient,
	}

	for _, option := range providerOptions {
		option(p)
	}

	if err := p.discover(); err != nil {
		return nil, err
	}

	return p, nil
}

func (p *Provider) discover() error {
	wellKnown := strings.TrimSuffix(p.issuer, "/") + DiscoveryEndpoint

	oidcConfig := &OidcConfiguration{}
	err := Get(wellKnown, oidcConfig, p.httpClient)
	if err != nil {
		return err
	}
	p.endpoint = oidcConfig.getEndpoints()
	return nil
}
