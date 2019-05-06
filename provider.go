package oidc

import (
	"net/http"
	"strings"

	"golang.org/x/oauth2"
)

const (
	DiscoveryEndpoint = "/.well-known/openid-configuration"
)

type Provider struct {
	issuer   string
	endpoint oauth2.Endpoint

	httpClient *http.Client
}

type oidcConfiguration struct {
	AuthURL  string
	TokenURL string
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

	oidcConfig := &oidcConfiguration{}
	err := Get(wellKnown, oidcConfig, p.httpClient)
	if err != nil {
		return err
	}
	p.endpoint = oauth2.Endpoint{
		AuthURL:  oidcConfig.AuthURL,
		TokenURL: oidcConfig.TokenURL,
	}
	return nil
}
