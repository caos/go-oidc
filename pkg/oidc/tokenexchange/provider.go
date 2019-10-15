package tokenexchange

import (
	"context"

	"golang.org/x/oauth2"

	"github.com/caos/go-oidc/pkg/oidc"
)

//ProviderTokenExchange extends the `Provider` interface for the *draft* oauth2 `Token Exchange`
type ProviderTokenExchange interface {
	oidc.Provider

	//TokenExchange implement the `Token Echange Grant` exchanging some token for an other
	TokenExchange(context.Context, *TokenExchangeRequest) (*oauth2.Token, error)
}

//ProviderTokenExchange extends the `ProviderTokenExchange` interface
//for the specific `delegation token` request
type ProviderDelegationTokenExchange interface {
	ProviderTokenExchange

	//DelegationTokenExchange implement the `Token Exchange Grant`
	//providing an access token in request for a `delegation` token for a given resource / audience
	DelegationTokenExchange(context.Context, string, ...TokenExchangeOption) (*oauth2.Token, error)
}
