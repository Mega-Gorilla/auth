package api

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"

	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"
	"github.com/supabase/auth/internal/conf"
	"github.com/supabase/auth/internal/models"
)

const (
	authentikUser        string = `{"iss":"https://authentik.example.com","sub":"7d5e3b6c-4f2a-1b8e-9d3c-5a2f8e1b4c7d","aud":"authentik-client-id","exp":1234567890,"iat":1234567890,"auth_time":1234567890,"nonce":"test-nonce","acr":"goauthentik.io/providers/oauth2/default","amr":["goauthentik.io/providers/oauth2/access_token"],"session_state":"test-session","email":"authentik@example.com","email_verified":true,"name":"Authentik Test User","given_name":"Authentik","family_name":"Test User","preferred_username":"authentikuser"}`
	authentikUserNoEmail string = `{"iss":"https://authentik.example.com","sub":"7d5e3b6c-4f2a-1b8e-9d3c-5a2f8e1b4c7d","aud":"authentik-client-id","exp":1234567890,"iat":1234567890,"auth_time":1234567890,"nonce":"test-nonce","acr":"goauthentik.io/providers/oauth2/default","amr":["goauthentik.io/providers/oauth2/access_token"],"session_state":"test-session","email_verified":false,"name":"Authentik Test User","given_name":"Authentik","family_name":"Test User","preferred_username":"authentikuser"}`
	authentikUserWrongEmail string = `{"iss":"https://authentik.example.com","sub":"7d5e3b6c-4f2a-1b8e-9d3c-5a2f8e1b4c7d","aud":"authentik-client-id","exp":1234567890,"iat":1234567890,"auth_time":1234567890,"nonce":"test-nonce","acr":"goauthentik.io/providers/oauth2/default","amr":["goauthentik.io/providers/oauth2/access_token"],"session_state":"test-session","email":"other@example.com","email_verified":true,"name":"Authentik Test User","given_name":"Authentik","family_name":"Test User","preferred_username":"authentikuser"}`
)

func (ts *ExternalTestSuite) TestSignupExternalAuthentik() {
	req := httptest.NewRequest(http.MethodGet, "http://localhost/authorize?provider=authentik", nil)
	w := httptest.NewRecorder()
	ts.API.handler.ServeHTTP(w, req)
	ts.Require().Equal(http.StatusFound, w.Code)
	u, err := url.Parse(w.Header().Get("Location"))
	ts.Require().NoError(err, "redirect url parse failed")
	ts.Require().Equal(ts.Config.External.Authentik.URL+"/authorize/", u.Scheme+"://"+u.Host+u.Path)
	q := u.Query()
	ts.Require().Equal(ts.Config.External.Authentik.RedirectURI, q.Get("redirect_uri"))
	ts.Require().Equal(ts.Config.External.Authentik.ClientID[0], q.Get("client_id"))
	ts.Require().Equal("code", q.Get("response_type"))
	ts.Require().Equal("openid profile email phone", q.Get("scope"))

	claims := ExternalProviderClaims{}
	p := jwt.NewParser(jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Name}))
	_, err = p.ParseWithClaims(q.Get("state"), &claims, func(token *jwt.Token) (interface{}, error) {
		return []byte(ts.Config.JWT.Secret), nil
	})
	ts.Require().NoError(err)

	ts.Require().Equal("authentik", claims.Provider)
	ts.Require().Equal(ts.Config.SiteURL, claims.SiteURL)
}

func AuthentikTestSignupSetup(ts *ExternalTestSuite, tokenCount *int, userCount *int, code string, user string) *httptest.Server {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/application/o/my-app/token/":
			*tokenCount++
			ts.Equal(code, r.FormValue("code"))
			ts.Equal("authorization_code", r.FormValue("grant_type"))
			ts.Equal(ts.Config.External.Authentik.RedirectURI, r.FormValue("redirect_uri"))

			w.Header().Add("Content-Type", "application/json")
			fmt.Fprint(w, `{"access_token":"authentik_token","refresh_token":"authentik_refresh_token","expires_in":86400,"token_type":"Bearer"}`)
		case "/application/o/my-app/userinfo/":
			*userCount++
			w.Header().Add("Content-Type", "application/json")
			fmt.Fprint(w, user)
		default:
			w.WriteHeader(http.StatusNotFound)
			ts.FailNow("unknown authentik oauth call %s", r.URL.Path)
		}
	}))

	ts.Config.External.Authentik = conf.OAuthProviderConfiguration{
		URL:         server.URL + "/application/o/my-app",
		RedirectURI: server.URL + "/callback",
		ClientID:    []string{"authentik-client-id"},
		Secret:      "authentik-secret",
		Enabled:     true,
	}

	return server
}

func (ts *ExternalTestSuite) TestSignupExternalAuthentik_AuthorizationCode() {
	tokenCount, userCount := 0, 0
	code := "authcode"
	server := AuthentikTestSignupSetup(ts, &tokenCount, &userCount, code, authentikUser)
	defer server.Close()

	u := performAuthorization(ts, "authentik", code, "")

	assertAuthorizationSuccess(ts, u, tokenCount, userCount, "authentik@example.com", "Authentik Test User", "7d5e3b6c-4f2a-1b8e-9d3c-5a2f8e1b4c7d", "https://authentik.example.com")
}

func (ts *ExternalTestSuite) TestSignupExternalAuthentikDisableSignupErrorWhenNoUser() {
	ts.Config.DisableSignup = true
	tokenCount, userCount := 0, 0
	code := "authcode"
	server := AuthentikTestSignupSetup(ts, &tokenCount, &userCount, code, authentikUser)
	defer server.Close()

	u := performAuthorization(ts, "authentik", code, "")

	assertAuthorizationFailure(ts, u, "Signups not allowed for this instance", "access_denied", "authentik@example.com")
}

func (ts *ExternalTestSuite) TestSignupExternalAuthentikDisableSignupErrorWhenNoEmail() {
	ts.Config.DisableSignup = true
	tokenCount, userCount := 0, 0
	code := "authcode"
	server := AuthentikTestSignupSetup(ts, &tokenCount, &userCount, code, authentikUserNoEmail)
	defer server.Close()

	u := performAuthorization(ts, "authentik", code, "")

	assertAuthorizationFailure(ts, u, "Error getting user email from external provider", "server_error", "")
}

func (ts *ExternalTestSuite) TestSignupExternalAuthentikDisableSignupSuccessWithPrimaryEmail() {
	ts.Config.DisableSignup = true

	ts.createUser("7d5e3b6c-4f2a-1b8e-9d3c-5a2f8e1b4c7d", "authentik@example.com", "Authentik Test User", "https://authentik.example.com", "")

	tokenCount, userCount := 0, 0
	code := "authcode"
	server := AuthentikTestSignupSetup(ts, &tokenCount, &userCount, code, authentikUser)
	defer server.Close()

	u := performAuthorization(ts, "authentik", code, "")

	assertAuthorizationSuccess(ts, u, tokenCount, userCount, "authentik@example.com", "Authentik Test User", "7d5e3b6c-4f2a-1b8e-9d3c-5a2f8e1b4c7d", "https://authentik.example.com")
}

func (ts *ExternalTestSuite) TestInviteTokenExternalAuthentikSuccessWhenMatchingToken() {
	// name and avatar should be populated from Authentik API
	ts.createUser("7d5e3b6c-4f2a-1b8e-9d3c-5a2f8e1b4c7d", "authentik@example.com", "", "", "invite_token")

	tokenCount, userCount := 0, 0
	code := "authcode"
	server := AuthentikTestSignupSetup(ts, &tokenCount, &userCount, code, authentikUser)
	defer server.Close()

	u := performAuthorization(ts, "authentik", code, "invite_token")

	assertAuthorizationSuccess(ts, u, tokenCount, userCount, "authentik@example.com", "Authentik Test User", "7d5e3b6c-4f2a-1b8e-9d3c-5a2f8e1b4c7d", "https://authentik.example.com")
}

func (ts *ExternalTestSuite) TestInviteTokenExternalAuthentikErrorWhenNoMatchingToken() {
	tokenCount, userCount := 0, 0
	code := "authcode"
	server := AuthentikTestSignupSetup(ts, &tokenCount, &userCount, code, authentikUser)
	defer server.Close()

	w := performAuthorizationRequest(ts, "authentik", "invite_token")
	ts.Require().Equal(http.StatusNotFound, w.Code)
}

func (ts *ExternalTestSuite) TestInviteTokenExternalAuthentikErrorWhenEmailDoesntMatch() {
	ts.createUser("7d5e3b6c-4f2a-1b8e-9d3c-5a2f8e1b4c7d", "authentik@example.com", "", "", "invite_token")

	tokenCount, userCount := 0, 0
	code := "authcode"
	server := AuthentikTestSignupSetup(ts, &tokenCount, &userCount, code, authentikUserWrongEmail)
	defer server.Close()

	u := performAuthorization(ts, "authentik", code, "invite_token")

	assertAuthorizationFailure(ts, u, "Invited email does not match emails from external provider", "invalid_request", "")
}

func (ts *ExternalTestSuite) TestSignupExternalAuthentikErrorWhenUserBanned() {
	tokenCount, userCount := 0, 0
	code := "authcode"
	server := AuthentikTestSignupSetup(ts, &tokenCount, &userCount, code, authentikUser)
	defer server.Close()

	u := performAuthorization(ts, "authentik", code, "")
	assertAuthorizationSuccess(ts, u, tokenCount, userCount, "authentik@example.com", "Authentik Test User", "7d5e3b6c-4f2a-1b8e-9d3c-5a2f8e1b4c7d", "https://authentik.example.com")

	user, err := models.FindUserByEmailAndAudience(ts.API.db, "authentik@example.com", ts.Config.JWT.Aud)
	require.NoError(ts.T(), err)
	require.NoError(ts.T(), user.Ban(ts.API.db))

	// User is banned, sign in again
	u = performAuthorization(ts, "authentik", code, "")
	assertAuthorizationFailure(ts, u, "User is banned", "access_denied", "authentik@example.com")
}

func (ts *ExternalTestSuite) TestSignupExternalAuthentikWithCustomClaims() {
	tokenCount, userCount := 0, 0
	code := "authcode"
	// User with custom claims
	userWithCustomClaims := `{"iss":"https://authentik.example.com","sub":"7d5e3b6c-4f2a-1b8e-9d3c-5a2f8e1b4c7d","aud":"authentik-client-id","exp":1234567890,"iat":1234567890,"auth_time":1234567890,"nonce":"test-nonce","acr":"goauthentik.io/providers/oauth2/default","amr":["goauthentik.io/providers/oauth2/access_token"],"session_state":"test-session","email":"authentik@example.com","email_verified":true,"name":"Authentik Test User","given_name":"Authentik","family_name":"Test User","preferred_username":"authentikuser","groups":["admin","users"],"department":"Engineering","custom_claim":"custom_value"}`
	server := AuthentikTestSignupSetup(ts, &tokenCount, &userCount, code, userWithCustomClaims)
	defer server.Close()

	u := performAuthorization(ts, "authentik", code, "")

	assertAuthorizationSuccess(ts, u, tokenCount, userCount, "authentik@example.com", "Authentik Test User", "7d5e3b6c-4f2a-1b8e-9d3c-5a2f8e1b4c7d", "https://authentik.example.com")

	// Verify custom claims were stored
	user, err := models.FindUserByEmailAndAudience(ts.API.db, "authentik@example.com", ts.Config.JWT.Aud)
	require.NoError(ts.T(), err)

	// Find the authentik identity
	for _, identity := range user.Identities {
		if identity.Provider == "authentik" {
			// Check that custom claims are stored
			customClaims, ok := identity.IdentityData["custom_claims"].(map[string]interface{})
			require.True(ts.T(), ok)
			require.Contains(ts.T(), customClaims, "groups")
			require.Contains(ts.T(), customClaims, "department")
			require.Contains(ts.T(), customClaims, "custom_claim")
			break
		}
	}
}