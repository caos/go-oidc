package oidc

import (
	"time"

	"gopkg.in/square/go-jose.v2"
)

type IDToken struct {
	Issuer                              string    `json:"iss,omitempty"`
	Subject                             string    `json:"sub,omitempty"`
	Audiences                           []string  `json:"aud,omitempty"`
	Expiration                          time.Time `json:"exp,omitempty"`
	IssuedAt                            time.Time `json:"iat,omitempty"`
	AuthTime                            time.Time `json:"auth_time,omitempty"`
	Nonce                               string    `json:"nonce,omitempty"`
	AuthenticationContextClassReference string    `json:"acr,omitempty"`
	AuthenticationMethodsReferences     []string  `json:"amr,omitempty"`
	AuthorizedParty                     string    `json:"azp,omitempty"`

	AtHash    string                  `json:"at_hash,omitempty"`
	Signature jose.SignatureAlgorithm //TODO: ???
}
