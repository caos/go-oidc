package main

import (
	"encoding/json"
	"log"
	"net/http"
	"time"

	"github.com/caos/go-oidc/pkg/oidc"
	"github.com/caos/go-oidc/pkg/oidc/defaults"
	"github.com/caos/utils/logging"
)

var (
	clientID     string = "TM-V3"
	clientSecret string = "changeme"
	issuer       string = "https://sta.accounts.abraxas.ch/"
	callbackPath string = "/auth/callback"

	publicURL         string = "/public"
	protectedURL      string = "/protected"
	protectedAdminURL string = "/protected/admin"
)

func main() {
	// ctx := context.Background()

	providerConfig := oidc.ProviderConfig{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Issuer:       issuer,
		// CallbackURL:  "http://localhost:5556" + callbackPath,
		// Scopes: []string{"openid", "profile", "email"},
	}
	provider, err := defaults.NewDefaultProvider(providerConfig, defaults.WithVerifierConfig(defaults.WithIssuedAtOffset(1*time.Second)))
	logging.Log("APP-nx6PeF").OnError(err).Panic("error creating provider")

	http.HandleFunc(publicURL, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("OK"))
	})

	http.HandleFunc(protectedURL, func(w http.ResponseWriter, r *http.Request) {
		ok, token := checkToken(w, r)
		if !ok {
			return
		}
		resp, err := provider.Introspect(r.Context(), token)
		if err != nil {
			http.Error(w, err.Error(), http.StatusForbidden)
			return
		}
		data, err := json.Marshal(resp)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Write(data)
	})

	http.HandleFunc(protectedAdminURL, func(w http.ResponseWriter, r *http.Request) {
		ok, token := checkToken(w, r)
		if !ok {
			return
		}
		tokens, err := provider.TokenExchange(r.Context(), oidc.NewTokenExchangeRequest(token, oidc.AccessTokenType, oidc.WithResource([]string{"Test"})))
		// defautlProv := provider.(*defaults.DefaultProvider)
		// tokens, err := defautlProv.DelegationTokenExchange(r.Context(), token, "Test")
		if err != nil {
			http.Error(w, "failed to exchange token: "+err.Error(), http.StatusUnauthorized)
			return
		}

		data, err := json.Marshal(tokens)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Write(data)
	})

	log.Printf("listening on http://%s/", "127.0.0.1:5557")
	log.Fatal(http.ListenAndServe("127.0.0.1:5557", nil))
}

func checkToken(w http.ResponseWriter, r *http.Request) (bool, string) {
	token := r.Header.Get("authorization")
	if token == "" {
		http.Error(w, "Auth header missing", http.StatusUnauthorized)
		return false, ""
	}
	return true, token
}
