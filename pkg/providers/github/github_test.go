package github

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

// tokenEqual returns whether the tokens are functionally equal for the purposes of the test.
func tokenEqual(issuer string, wantToken, gotToken *jsonToken) bool {
	if wantToken == nil && gotToken == nil {
		return true
	}

	if gotToken == nil || wantToken == nil {
		return false
	}

	// NOTE: don't check the wantToken issuer because it's not known until the
	// server is created and we can't use a dummy value because verification checks
	// it.
	if want, got := issuer, gotToken.Issuer; want != got {
		return false
	}

	if len(wantToken.Audience) != len(gotToken.Audience) {
		return false
	}

	for i := range wantToken.Audience {
		if wantToken.Audience[i] != gotToken.Audience[i] {
			return false
		}
	}

	if want, got := wantToken.Expiry, gotToken.Expiry; want != got {
		return false
	}

	return true
}

func TestToken(t *testing.T) {
	now := time.Date(2022, 4, 14, 12, 24, 0, 0, time.UTC)

	testCases := []struct {
		name     string
		audience string
		token    *jsonToken
		status   int
		raw      string
		err      error
	}{
		{
			name:     "basic token",
			audience: "hoge",
			token: &jsonToken{
				Audience: []string{"hoge"},
				Expiry:   now.Add(1 * time.Hour).Unix(),
			},
		},
		{
			name:     "expired token",
			audience: "hoge",
			token: &jsonToken{
				Audience: []string{"hoge"},
				Expiry:   now.Add(-1 * time.Hour).Unix(),
			},
			err: &errVerify{},
		},
		{
			name:     "bad audience",
			audience: "hoge",
			token: &jsonToken{
				Audience: []string{"fuga"},
				Expiry:   now.Add(1 * time.Hour).Unix(),
			},
			err: &errVerify{},
		},
		{
			name:     "bad issuer",
			audience: "hoge",
			token: &jsonToken{
				Issuer:   "https://www.google.com/",
				Audience: []string{"hoge"},
				Expiry:   now.Add(1 * time.Hour).Unix(),
			},
			err: &errVerify{},
		},
		{
			name:     "invalid response",
			audience: "hoge",
			raw:      `not json`,
			status:   http.StatusOK,
			err:      &errToken{},
		},
		{
			name:     "invalid parts",
			audience: "hoge",
			raw:      `{"value": "part1"}`,
			status:   http.StatusOK,
			err:      &errToken{},
		},
		{
			name:     "invalid base64",
			audience: "hoge",
			raw:      `{"value": "part1.part2.part3"}`,
			status:   http.StatusOK,
			err:      &errToken{},
		},
		{
			name:     "invalid json",
			audience: "hoge",
			raw:      fmt.Sprintf(`{"value": "part1.%s.part3"}`, base64.RawURLEncoding.EncodeToString([]byte("not json"))),
			status:   http.StatusOK,
			err:      &errToken{},
		},
		{
			name:     "error response",
			audience: "hoge",
			raw:      "",
			status:   http.StatusServiceUnavailable,
			err:      &errRequest{},
		},
		{
			name:     "redirect response",
			audience: "hoge",
			raw:      "",
			status:   http.StatusFound,
			err:      &errRequest{},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var s *httptest.Server
			var ga *githubActions
			if tc.token != nil {
				s, ga = newTestOIDCServerWithToken(t, now, *tc.token)
			} else {
				s, ga = newRawTestOIDCServer(t, now, tc.status, tc.raw)
			}
			defer s.Close()

			tokenPayload, err := ga.Provide(context.Background(), tc.audience)
			if err != nil {
				if tc.err != nil {
					if !errors.As(err, &tc.err) {
						t.Fatalf("unexpected error: %v", cmp.Diff(err, tc.err, cmpopts.EquateErrors()))
					}
				} else {
					t.Fatalf("unexpected error: %v", cmp.Diff(err, tc.err, cmpopts.EquateErrors()))
				}
			} else {
				if tc.err != nil {
					t.Fatalf("unexpected error: %v", cmp.Diff(err, tc.err, cmpopts.EquateErrors()))
				} else {
					// Successful response, as expected. Check token.
					parts := strings.Split(tokenPayload, ".")
					if len(parts) < 2 {
						t.Fatalf("decoding payload: too few jwt parts: %d", len(parts))
					}

					decoded, err := base64.RawURLEncoding.DecodeString(parts[1])
					if err != nil {
						t.Fatalf("decoding payload: %v", err)
					}

					var token jsonToken
					if err := json.Unmarshal(decoded, &token); err != nil {
						t.Fatalf("decoding payload: %v", err)
					}

					if want, got := tc.token, &token; !tokenEqual(s.URL, want, got) {
						t.Errorf("unexpected workflow ref\nwant: %#v\ngot:  %#v\ndiff:\n%v", want, got, cmp.Diff(want, got))
					}
				}
			}
		})
	}
}
