// Copyright © 2025 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package integration_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/magiconair/properties/assert"
	"github.com/stretchr/testify/require"
	goauth "golang.org/x/oauth2"

	"github.com/ory/fosite"
	"github.com/ory/fosite/compose"
	"github.com/ory/fosite/handler/oauth2" // "github.com/stretchr/testify/assert"
	"github.com/ory/fosite/storage"
)

func TestAuthorizeCodeFlowWithPublicClientAndPKCE(t *testing.T) {
	for _, strategy := range []oauth2.AccessTokenStrategy{
		hmacStrategy,
	} {
		runAuthorizeCodeGrantWithPublicClientAndPKCETest(t, strategy)
	}
}

func runAuthorizeCodeGrantWithPublicClientAndPKCETest(t *testing.T, strategy interface{}) {
	c := new(fosite.Config)
	c.EnforcePKCE = true
	c.EnablePKCEPlainChallengeMethod = true
	f := compose.Compose(c, fositeStore, strategy, compose.OAuth2AuthorizeExplicitFactory, compose.OAuth2PKCEFactory, compose.OAuth2TokenIntrospectionFactory)
	ts := mockServer(t, f, &fosite.DefaultSession{})
	defer ts.Close()

	oauthClient := newOAuth2Client(ts)
	oauthClient.ClientSecret = ""
	oauthClient.ClientID = "public-client"
	fositeStore.Clients["public-client"].(*fosite.DefaultClient).RedirectURIs[0] = ts.URL + "/callback"

	var authCodeUrl string
	var verifier string
	for k, c := range []struct {
		description     string
		setup           func()
		authStatusCode  int
		tokenStatusCode int
	}{
		{
			description: "should fail because no challenge was given",
			setup: func() {
				authCodeUrl = oauthClient.AuthCodeURL("12345678901234567890")
			},
			authStatusCode: http.StatusNotAcceptable,
		},
		{
			description: "should pass",
			setup: func() {
				verifier = "somechallengesomechallengesomechallengesomechallengesomechallengesomechallenge"
				authCodeUrl = oauthClient.AuthCodeURL("12345678901234567890") + "&code_challenge=somechallengesomechallengesomechallengesomechallengesomechallengesomechallenge"
			},
			authStatusCode: http.StatusOK,
		},
		{
			description: "should fail because the verifier is mismatching",
			setup: func() {
				verifier = "failchallengefailchallengefailchallengefailchallengefailchallengefailchallengefailchallengefailchallenge"
				authCodeUrl = oauthClient.AuthCodeURL("12345678901234567890") + "&code_challenge=somechallengesomechallengesomechallengesomechallengesomechallengesomechallengesomechallengesomechallenge"
			},
			authStatusCode:  http.StatusOK,
			tokenStatusCode: http.StatusBadRequest,
		},
	} {
		t.Run(fmt.Sprintf("case=%d/description=%s", k, c.description), func(t *testing.T) {
			c.setup()

			t.Logf("Got url: %s", authCodeUrl)

			resp, err := http.Get(authCodeUrl)
			require.NoError(t, err)
			require.Equal(t, resp.StatusCode, c.authStatusCode)

			if resp.StatusCode == http.StatusOK {
				// This should fail because no verifier was given
				// _, err := oauthClient.Exchange(goauth.NoContext, resp.Request.URL.Query().Get("code"))
				// require.Error(t, err)
				// require.Empty(t, token.AccessToken)
				t.Logf("Got redirect url: %s", resp.Request.URL)

				resp, err := http.PostForm(ts.URL+"/token", url.Values{
					"code":          {resp.Request.URL.Query().Get("code")},
					"grant_type":    {"authorization_code"},
					"client_id":     {"public-client"},
					"redirect_uri":  {ts.URL + "/callback"},
					"code_verifier": {verifier},
				})
				require.NoError(t, err)
				defer resp.Body.Close()

				body, err := io.ReadAll(resp.Body)
				require.NoError(t, err)

				if c.tokenStatusCode != 0 {
					require.Equal(t, c.tokenStatusCode, resp.StatusCode)
					token := goauth.Token{}
					require.NoError(t, json.Unmarshal(body, &token))
					require.Empty(t, token.AccessToken)
					return
				}

				assert.Equal(t, resp.StatusCode, http.StatusOK)
				token := goauth.Token{}
				require.NoError(t, json.Unmarshal(body, &token))

				require.NotEmpty(t, token.AccessToken, "Got body: %s", string(body))

				httpClient := oauthClient.Client(goauth.NoContext, &token)
				resp, err = httpClient.Get(ts.URL + "/info")
				require.NoError(t, err)
				assert.Equal(t, http.StatusOK, resp.StatusCode)
			}
		})
	}
}

// The verifier and S256 challenge are the RFC 7636 Appendix B test vector.
const pkceVerifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"

type pkceLifecycleStore struct {
	*storage.MemoryStore
	invalidateError error
	accessError     error
	deleteError     error
	beforePKCERead  func(context.Context)
}

func (s *pkceLifecycleStore) GetPKCERequestSession(ctx context.Context, signature string, session fosite.Session) (fosite.Requester, error) {
	if s.beforePKCERead != nil {
		s.beforePKCERead(ctx)
	}
	return s.MemoryStore.GetPKCERequestSession(ctx, signature, session)
}

func (s *pkceLifecycleStore) InvalidateAuthorizeCodeSession(ctx context.Context, signature string) error {
	if s.invalidateError != nil {
		return s.invalidateError
	}
	return s.MemoryStore.InvalidateAuthorizeCodeSession(ctx, signature)
}

func (s *pkceLifecycleStore) CreateAccessTokenSession(ctx context.Context, signature string, request fosite.Requester) error {
	if s.accessError != nil {
		return s.accessError
	}
	return s.MemoryStore.CreateAccessTokenSession(ctx, signature, request)
}

func (s *pkceLifecycleStore) DeletePKCERequestSession(ctx context.Context, signature string) error {
	if s.deleteError != nil {
		return s.deleteError
	}
	return s.MemoryStore.DeletePKCERequestSession(ctx, signature)
}

// Stage issuance writes until Commit so failures exercise the existing
// authorization-code transaction without a transaction around the exchange.
type pkceTransactionalStore struct {
	*pkceLifecycleStore
	commitError error
}

type pkceTransactionKey struct{}
type pkceTransaction struct {
	code, access string
	request      fosite.Requester
}

func (s *pkceTransactionalStore) BeginTX(ctx context.Context) (context.Context, error) {
	return context.WithValue(ctx, pkceTransactionKey{}, &pkceTransaction{}), nil
}

func (s *pkceTransactionalStore) InvalidateAuthorizeCodeSession(ctx context.Context, signature string) error {
	ctx.Value(pkceTransactionKey{}).(*pkceTransaction).code = signature
	return nil
}

func (s *pkceTransactionalStore) CreateAccessTokenSession(ctx context.Context, signature string, request fosite.Requester) error {
	if s.accessError != nil {
		return s.accessError
	}
	tx := ctx.Value(pkceTransactionKey{}).(*pkceTransaction)
	tx.access, tx.request = signature, request
	return nil
}

func (s *pkceTransactionalStore) Commit(ctx context.Context) error {
	if s.commitError != nil {
		return s.commitError
	}
	tx := ctx.Value(pkceTransactionKey{}).(*pkceTransaction)
	if err := s.MemoryStore.InvalidateAuthorizeCodeSession(ctx, tx.code); err != nil {
		return err
	}
	return s.MemoryStore.CreateAccessTokenSession(ctx, tx.access, tx.request)
}

func (s *pkceTransactionalStore) Rollback(context.Context) error { return nil }

type pkceFailingHandler struct {
	fosite.TokenEndpointHandler
	requestError, responseError error
}

func (h *pkceFailingHandler) HandleTokenEndpointRequest(ctx context.Context, request fosite.AccessRequester) error {
	return h.requestError
}

func (h *pkceFailingHandler) PopulateTokenEndpointResponse(ctx context.Context, request fosite.AccessRequester, response fosite.AccessResponder) error {
	return h.responseError
}

func newPKCELifecycleFlow(t *testing.T, store interface{}, memory *storage.MemoryStore, public, withPKCE bool) (fosite.OAuth2Provider, *fosite.Config, string) {
	t.Helper()
	config := &fosite.Config{
		GlobalSecret:                []byte("a-test-secret-with-at-least-32-bytes"),
		EnforcePKCEForPublicClients: true,
	}
	memory.Clients["client"] = &fosite.DefaultClient{
		ID: "client", Public: public,
		Secret:        []byte(`$2a$10$IxMdI6d.LIRZPpSfEwNoeu4rY3FhDREsxFJXikcgdRRAStxUlsuEO`), // foobar
		RedirectURIs:  []string{"https://client.example/callback"},
		GrantTypes:    []string{"authorization_code"},
		ResponseTypes: []string{"code"},
	}
	f := compose.Compose(config, store, compose.NewOAuth2HMACStrategy(config), compose.OAuth2AuthorizeExplicitFactory, compose.OAuth2PKCEFactory)
	form := url.Values{
		"client_id": {"client"}, "response_type": {"code"},
		"redirect_uri": {"https://client.example/callback"}, "state": {"long-enough-state"},
	}
	if withPKCE {
		form.Set("code_challenge", "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM")
		form.Set("code_challenge_method", "S256")
	}
	ar, err := f.NewAuthorizeRequest(context.Background(), httptest.NewRequest(http.MethodGet, "https://server.example/auth?"+form.Encode(), nil))
	require.NoError(t, err)
	response, err := f.NewAuthorizeResponse(context.Background(), ar, &fosite.DefaultSession{})
	require.NoError(t, err)
	return f, config, response.GetCode()
}

func pkceAccessRequest(ctx context.Context, f fosite.OAuth2Provider, code, verifier string, public bool) (fosite.AccessRequester, error) {
	form := url.Values{
		"client_id": {"client"}, "grant_type": {"authorization_code"},
		"code": {code}, "redirect_uri": {"https://client.example/callback"},
	}
	if verifier != "" {
		form.Set("code_verifier", verifier)
	}
	r := httptest.NewRequest(http.MethodPost, "https://server.example/token", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if !public {
		r.SetBasicAuth("client", "foobar")
	}
	return f.NewAccessRequest(ctx, r, &fosite.DefaultSession{})
}

func TestPKCELifecycleRetries(t *testing.T) {
	for _, public := range []bool{false, true} {
		t.Run(fmt.Sprintf("public=%t", public), func(t *testing.T) {
			store := storage.NewMemoryStore()
			f, _, code := newPKCELifecycleFlow(t, store, store, public, true)
			ctx := context.Background()
			_, err := pkceAccessRequest(ctx, f, code, strings.Repeat("x", 43), public)
			require.ErrorIs(t, err, fosite.ErrInvalidGrant)
			_, err = pkceAccessRequest(ctx, f, code, "", public)
			require.ErrorIs(t, err, fosite.ErrInvalidGrant)
			request, err := pkceAccessRequest(ctx, f, code, pkceVerifier, public)
			require.NoError(t, err)
			response, err := f.NewAccessResponse(ctx, request)
			require.NoError(t, err)
			require.NotEmpty(t, response.GetAccessToken())
			require.Empty(t, store.PKCES)
			_, err = pkceAccessRequest(ctx, f, code, pkceVerifier, public)
			require.ErrorIs(t, err, fosite.ErrInvalidGrant)
		})
	}
	t.Run("confidential client without PKCE", func(t *testing.T) {
		store := &pkceLifecycleStore{MemoryStore: storage.NewMemoryStore(), deleteError: errors.New("no PKCE session to delete")}
		f, _, code := newPKCELifecycleFlow(t, store, store.MemoryStore, false, false)
		request, err := pkceAccessRequest(context.Background(), f, code, "", false)
		require.NoError(t, err)
		response, err := f.NewAccessResponse(context.Background(), request)
		require.NoError(t, err)
		require.NotEmpty(t, response.GetAccessToken())
	})
}

func TestPKCELifecycleIssuanceFailures(t *testing.T) {
	for _, stage := range []string{"later request handler", "later response handler", "invalidation", "access storage", "transaction access storage", "transaction commit", "cleanup", "handler ordering"} {
		t.Run(stage, func(t *testing.T) {
			store := &pkceLifecycleStore{MemoryStore: storage.NewMemoryStore()}
			txStore := &pkceTransactionalStore{pkceLifecycleStore: store}
			var backend interface{} = store
			if strings.HasPrefix(stage, "transaction") {
				backend = txStore
			}
			f, config, code := newPKCELifecycleFlow(t, backend, store.MemoryStore, false, true)
			ctx := context.Background()
			failure := fosite.ErrServerError.WithDebug("issuance failed")
			if stage == "later request handler" || stage == "later response handler" {
				handler := &pkceFailingHandler{TokenEndpointHandler: config.TokenEndpointHandlers[1]}
				config.TokenEndpointHandlers = append(config.TokenEndpointHandlers, handler)
				if stage == "later request handler" {
					handler.requestError = failure
				} else {
					handler.responseError = failure
				}
			}
			request, err := pkceAccessRequest(ctx, f, code, pkceVerifier, false)
			if stage == "later request handler" {
				require.ErrorIs(t, err, fosite.ErrServerError)
				config.TokenEndpointHandlers = config.TokenEndpointHandlers[:2]
				_, err = pkceAccessRequest(ctx, f, code, "", false)
				require.ErrorIs(t, err, fosite.ErrInvalidGrant)
				request, err = pkceAccessRequest(ctx, f, code, pkceVerifier, false)
				require.NoError(t, err)
				response, err := f.NewAccessResponse(ctx, request)
				require.NoError(t, err)
				require.NotEmpty(t, response.GetAccessToken())
				return
			}
			require.NoError(t, err)
			switch stage {
			case "invalidation":
				store.invalidateError = failure
			case "access storage", "transaction access storage":
				store.accessError = failure
			case "transaction commit":
				txStore.commitError = failure
			case "cleanup":
				store.deleteError = failure
			case "handler ordering":
				config.TokenEndpointHandlers[0], config.TokenEndpointHandlers[1] = config.TokenEndpointHandlers[1], config.TokenEndpointHandlers[0]
			}
			response, err := f.NewAccessResponse(ctx, request)
			require.ErrorIs(t, err, fosite.ErrServerError)
			require.Nil(t, response)
			store.invalidateError, store.accessError, store.deleteError, txStore.commitError = nil, nil, nil, nil
			if stage == "handler ordering" {
				config.TokenEndpointHandlers[0], config.TokenEndpointHandlers[1] = config.TokenEndpointHandlers[1], config.TokenEndpointHandlers[0]
			}
			_, err = pkceAccessRequest(ctx, f, code, "", false)
			require.Error(t, err, "an issuance failure must not make a missing verifier acceptable")
			request, err = pkceAccessRequest(ctx, f, code, pkceVerifier, false)
			if stage == "access storage" || stage == "cleanup" || stage == "later response handler" {
				// Without a transaction, invalidation cannot be rolled back.
				require.ErrorIs(t, err, fosite.ErrInvalidGrant)
				return
			}
			require.NoError(t, err, "a still-usable code must retain its challenge")
			response, err = f.NewAccessResponse(ctx, request)
			require.NoError(t, err)
			require.NotEmpty(t, response.GetAccessToken())
			require.Empty(t, store.PKCES)
		})
	}
}

func TestPKCELifecycleConcurrentCleanup(t *testing.T) {
	for _, redeem := range []bool{false, true} {
		t.Run(fmt.Sprintf("redeem=%t", redeem), func(t *testing.T) {
			store := &pkceLifecycleStore{MemoryStore: storage.NewMemoryStore()}
			f, _, code := newPKCELifecycleFlow(t, store, store.MemoryStore, false, true)
			type pausedRequestKey struct{}
			paused, resume := make(chan struct{}), make(chan struct{})
			store.beforePKCERead = func(ctx context.Context) {
				if ctx.Value(pausedRequestKey{}) != nil {
					close(paused)
					<-resume
				}
			}
			result := make(chan error, 1)
			go func() {
				ctx := context.WithValue(context.Background(), pausedRequestKey{}, true)
				request, err := pkceAccessRequest(ctx, f, code, "", false)
				if err == nil {
					_, err = f.NewAccessResponse(ctx, request)
				}
				result <- err
			}()
			select {
			case <-paused: // The omitted-verifier exchange has already read a valid code.
			case err := <-result:
				t.Fatalf("exchange failed before reaching PKCE: %v", err)
			case <-time.After(10 * time.Second):
				close(resume)
				t.Fatal("exchange did not reach PKCE")
			}
			ctx := context.Background()
			verifier := strings.Repeat("x", 43)
			if redeem {
				verifier = pkceVerifier
			}
			request, err := pkceAccessRequest(ctx, f, code, verifier, false)
			var response fosite.AccessResponder
			if err == nil {
				response, err = f.NewAccessResponse(ctx, request)
			}
			close(resume)
			concurrentErr := <-result
			if redeem {
				require.NoError(t, err)
				require.NotEmpty(t, response.GetAccessToken())
				// PKCE data is now gone, but issuance rechecks the invalidated code.
				require.ErrorIs(t, concurrentErr, fosite.ErrServerError)
			} else {
				require.ErrorIs(t, err, fosite.ErrInvalidGrant)
				require.ErrorIs(t, concurrentErr, fosite.ErrInvalidGrant)
				request, err = pkceAccessRequest(ctx, f, code, pkceVerifier, false)
				require.NoError(t, err)
				response, err = f.NewAccessResponse(ctx, request)
				require.NoError(t, err)
				require.NotEmpty(t, response.GetAccessToken())
			}
		})
	}
}
