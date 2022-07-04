package github

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"gopkg.in/square/go-jose.v2"
)

type jsonToken struct {
	Issuer   string   `json:"iss"`
	Audience []string `json:"aud"`
	Expiry   int64    `json:"exp"`
}

// testKeySet is a oidc.KeySet that can be used in tests.
type testKeySet struct{}

// VerifySignature implements oidc.KeySet.VerifySignature.
func (ks *testKeySet) VerifySignature(ctx context.Context, jwt string) ([]byte, error) {
	// NOTE: Doesn't actually verify, just parses out the payload from the token.
	parts := strings.Split(jwt, ".")
	if len(parts) < 2 {
		return nil, fmt.Errorf("jwt parts: %d", len(parts))
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("jwt payload: %v", err)
	}
	return payload, nil
}

// newTestOIDCServerWithToken returns an `httptest.Server` that can be used as
// an OIDC server and a `githubActions` instance that will use the test server.
// The server returns the given token when queried. `now` is the time used for
// token expiration verification by the client.
func newTestOIDCServerWithToken(t *testing.T, now time.Time, token jsonToken) (*httptest.Server, *githubActions) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: privateKey}, nil)
	if err != nil {
		t.Fatal(err)
	}

	// NOTE: issuerURL needs to be set after the server is instantiated, but is
	// also used when serving requests.
	var issuerURL string
	s, c := newTestOIDCServer(t, now, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Allow the token to override the issuer for verification testing.
		issuer := issuerURL
		if token.Issuer != "" {
			issuer = token.Issuer
		}

		b, err := json.Marshal(jsonToken{
			Issuer:   issuer,
			Audience: token.Audience,
			Expiry:   token.Expiry,
		})
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		object, err := signer.Sign(b)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		value, err := object.CompactSerialize()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		fmt.Printf("value: %q\n", value)
		fmt.Fprintf(w, `{"value": "%s"}`, value)
	}))
	issuerURL = s.URL

	return s, c
}

// newRawTestOIDCServer returns an `httptest.Server` that can be used as an
// OIDC server and a `githubActions` instance that will use the test server.
// The server returns the raw value given as a response. `now` is the time used
// for token expiration verification by the client.
func newRawTestOIDCServer(t *testing.T, now time.Time, status int, raw string) (*httptest.Server, *githubActions) {
	return newTestOIDCServer(t, now, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Respond with a very basic 3-part JWT token.
		w.WriteHeader(status)
		fmt.Fprintln(w, raw)
	}))
}

// newTestOIDCServer returns an `httptest.Server` that can be used as an
// OIDC server and a `githubActions` instance that will use the test server.
// The server handles the token request using the given `http.HandlerFunc`. `now`
// is the time used for token expiration verification by the client.
func newTestOIDCServer(t *testing.T, now time.Time, f http.HandlerFunc) (*httptest.Server, *githubActions) {
	// NOTE: issuerURL needs to be set after the server is instantiated, but is
	// also used when serving requests.
	var issuerURL string
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			f(w, r)
		case "/.well-known/openid-configuration":
			// Return very basic provider info in case it's requested.
			fmt.Fprintf(w, `{"issuer": %q, "token_endpoint": %q}`, issuerURL, issuerURL)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	issuerURL = s.URL

	ga := githubActions{
		providerURL: func() (*url.URL, error) { return url.ParseRequestURI(s.URL) },
		verifierFunc: func(ctx context.Context) (*oidc.IDTokenVerifier, error) {
			return oidc.NewVerifier(s.URL, &testKeySet{}, &oidc.Config{
				Now:               func() time.Time { return now },
				SkipClientIDCheck: true,
			}), nil
		},
	}

	return s, &ga
}
