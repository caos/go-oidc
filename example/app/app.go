package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"

	"golang.org/x/oauth2"

	"github.com/caos/go-oidc/pkg/oidc"
	"github.com/caos/go-oidc/pkg/oidc/defaults"
	"github.com/caos/utils/logging"
)

var (
	clientID     string = "TM-V3"
	clientSecret string = "changeme"
	issuer       string = "https://sta.accounts.abraxas.ch/"
	callbackPath string = "/auth/callback"
)

func main() {
	ctx := context.Background()

	providerConfig := oidc.ProviderConfig{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Issuer:       issuer,
		CallbackURL:  "http://localhost:5556" + callbackPath,
		Scopes:       []string{"openid", "profile", "email"},
	}
	provider, err := defaults.NewDefaultProvider(providerConfig)
	logging.Log("APP-nx6PeF").OnError(err).Panic("error creating provider")

	state := "foobar"

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, provider.AuthURL(state), http.StatusFound)
	})

	http.HandleFunc(callbackPath, func(w http.ResponseWriter, r *http.Request) {
		token, err := provider.CodeExchange(ctx, r.URL.Query().Get("code"))
		if err != nil {
			http.Error(w, "failed to exchange token: "+err.Error(), http.StatusUnauthorized)
			return
		}

		tokens := struct {
			*oauth2.Token
			IDToken string        `json:"id_token"`
			Claims  *oidc.IDToken `json:"claims"`
		}{
			token,
			token.Extra("id_token").(string),
			token.Extra("id_token").(string),
		}
		data, err := json.Marshal(tokens)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Write(data)
	})
	log.Printf("listening on http://%s/", "127.0.0.1:5556")
	log.Fatal(http.ListenAndServe("127.0.0.1:5556", nil))
}
