//
// Copyright 2021 The Sigstore Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package github

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/sigstore/cosign/pkg/providers"
)

const (
	// RequestTokenEnvKey is the environment variable containing the Bearer
	// token for the request to the OIDC provider.
	RequestTokenEnvKey = "ACTIONS_ID_TOKEN_REQUEST_TOKEN"

	// RequestURLEnvKey is the environment variable containing the URL for
	// GitHub's OIDC provider.
	RequestURLEnvKey = "ACTIONS_ID_TOKEN_REQUEST_URL"
)

// actionsProviderURL is the url of the GitHub OIDC providern(issuer).
const actionsProviderURL = "https://token.actions.githubusercontent.com"

func init() {
	providers.Register("github-actions", &githubActions{
		providerURL: func() (*url.URL, error) { return url.ParseRequestURI(os.Getenv(RequestURLEnvKey)) },
		verifierFunc: func(ctx context.Context) (*oidc.IDTokenVerifier, error) {
			provider, err := oidc.NewProvider(ctx, actionsProviderURL)
			if err != nil {
				return nil, err
			}
			return provider.Verifier(&oidc.Config{
				// NOTE: Disable ClientID check.
				// ClientID is normally checked to be part of the audience but we
				// don't use a ClientID when requesting a token.
				SkipClientIDCheck: true,
			}), nil
		},
	})
}

type githubActions struct {
	// providerURL returns the URL used for requesting OIDC tokens.
	providerURL func() (*url.URL, error)
	// verifierFunc returns an OIDC verifier that can be used to verify tokens.
	verifierFunc func(ctx context.Context) (*oidc.IDTokenVerifier, error)
}

var _ providers.Interface = (*githubActions)(nil)

// wrappable is a simple interface that allows wrapping an error with a custom
// error type.
type wrappable interface {
	Error() string
	setWrapped(error)
}

// githubProviderError is a base wrappable implementation.
type githubProviderError struct {
	wrapped error
}

func (err *githubProviderError) Error() string {
	return err.wrapped.Error()
}

func (err *githubProviderError) UnWrap() error {
	return err.wrapped
}

func (err *githubProviderError) setWrapped(wrapped error) {
	err.wrapped = wrapped
}

// errorf returns a new error that creates a new error and wraps it in the
// given wrappable instance. This allows the easy use of errors.As and
// errors.Is.
func errorf(err wrappable, format string, a ...interface{}) error {
	err.setWrapped(fmt.Errorf(format, a...))
	return err
}

type errRequest struct {
	githubProviderError
}

type errToken struct {
	githubProviderError
}

type errVerify struct {
	githubProviderError
}

// Enabled implements providers.Interface
func (ga *githubActions) Enabled(ctx context.Context) bool {
	if os.Getenv(RequestTokenEnvKey) == "" {
		return false
	}
	if os.Getenv(RequestURLEnvKey) == "" {
		return false
	}
	return true
}

// Provide implements providers.Interface
func (ga *githubActions) Provide(ctx context.Context, audience string) (string, error) {
	url, err := ga.requestURL(audience)
	if err != nil {
		return "", errorf(&errRequest{}, "request url: %w", err)
	}

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", errorf(&errRequest{}, "creating request: %w", err)
	}

	req.Header.Add("Authorization", "bearer "+os.Getenv(RequestTokenEnvKey))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", errorf(&errRequest{}, "request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", errorf(&errRequest{}, "response: %s", resp.Status)
	}

	var payload struct {
		Value string `json:"value"`
	}

	decoder := json.NewDecoder(resp.Body)
	if err := decoder.Decode(&payload); err != nil {
		return "", errorf(&errToken{}, "parsing JSON: %w", err)
	}

	return ga.verifyToken(ctx, audience, payload.Value)
}

func (ga *githubActions) requestURL(audience string) (string, error) {
	requestURL, err := ga.providerURL()
	if err != nil {
		return "", err
	}
	q := requestURL.Query()
	q.Add("audience", audience)
	requestURL.RawQuery = q.Encode()
	return requestURL.String(), nil
}

// verifyToken verifies the token using a go-oidc verifier.
func (ga *githubActions) verifyToken(ctx context.Context, audience string, payload string) (string, error) {
	verifier, err := ga.verifierFunc(ctx)
	if err != nil {
		return "", errorf(&errVerify{}, "creating verifier: %w", err)
	}

	// Verify checks the issuer, expiry, and signature.
	t, err := verifier.Verify(ctx, payload)
	if err != nil {
		return "", errorf(&errVerify{}, "failed verification: %w", err)
	}

	// Verify the audience returned was the one we requested.
	if len(t.Audience) != 1 || t.Audience[0] != audience {
		return "", errorf(&errVerify{}, "audience not equal %q != %q", audience, t.Audience)
	}

	// Return the payload only if verified.
	return payload, nil
}
