package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"

	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"github.com/supabase/auth/internal/conf"
	"github.com/supabase/auth/internal/models"
)

type AuthentikTestSuite struct {
	suite.Suite
	API    *API
	Config *conf.GlobalConfiguration
}

func (ts *AuthentikTestSuite) SetupTest() {
	api, config, err := setupAPIForTest()
	require.NoError(ts.T(), err)

	ts.API = api
	ts.Config = config
}

func AuthentikTestSignupSetup(ts *AuthentikTestSuite, tokenCount *int, userCount *int, code string, user string) *httptest.Server {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/application/o/my-app/token/":
			*tokenCount++
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

// AuthentikTestUser represents the user data returned by Authentik
const (
	authentikUser        string = `{"iss":"https://authentik.example.com","sub":"7d5e3b6c-4f2a-1b8e-9d3c-5a2f8e1b4c7d","aud":"authentik-client-id","exp":1234567890,"iat":1234567890,"auth_time":1234567890,"nonce":"test-nonce","acr":"goauthentik.io/providers/oauth2/default","amr":["goauthentik.io/providers/oauth2/access_token"],"session_state":"test-session","email":"authentik@example.com","email_verified":true,"name":"Authentik Test User","given_name":"Authentik","family_name":"Test User","preferred_username":"authentikuser"}`
	authentikUserNoEmail string = `{"iss":"https://authentik.example.com","sub":"7d5e3b6c-4f2a-1b8e-9d3c-5a2f8e1b4c7d","aud":"authentik-client-id","exp":1234567890,"iat":1234567890,"auth_time":1234567890,"nonce":"test-nonce","acr":"goauthentik.io/providers/oauth2/default","amr":["goauthentik.io/providers/oauth2/access_token"],"session_state":"test-session","email_verified":false,"name":"Authentik Test User","given_name":"Authentik","family_name":"Test User","preferred_username":"authentikuser"}`
	authentikUserWrongEmail string = `{"iss":"https://authentik.example.com","sub":"7d5e3b6c-4f2a-1b8e-9d3c-5a2f8e1b4c7d","aud":"authentik-client-id","exp":1234567890,"iat":1234567890,"auth_time":1234567890,"nonce":"test-nonce","acr":"goauthentik.io/providers/oauth2/default","amr":["goauthentik.io/providers/oauth2/access_token"],"session_state":"test-session","email":"other@example.com","email_verified":true,"name":"Authentik Test User","given_name":"Authentik","family_name":"Test User","preferred_username":"authentikuser"}`
)

func (ts *AuthentikTestSuite) TestSignupExternalAuthentik() {
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
	ts.Require().Equal("openid profile email", q.Get("scope"))

	claims := ExternalProviderClaims{}
	p := jwt.NewParser(jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Name}))
	_, err = p.ParseWithClaims(q.Get("state"), &claims, func(token *jwt.Token) (interface{}, error) {
		return []byte(ts.Config.JWT.Secret), nil
	})
	ts.Require().NoError(err)

	ts.Require().Equal("authentik", claims.Provider)
	ts.Require().Equal(ts.Config.SiteURL, claims.SiteURL)
}

func (ts *AuthentikTestSuite) TestSignupExternalAuthentik_AuthorizationCode() {
	tokenCount, userCount := 0, 0
	code := "authcode"
	server := AuthentikTestSignupSetup(ts, &tokenCount, &userCount, code, authentikUser)
	defer server.Close()

	u := performAuthorization(ts, "authentik", code, "")

	assertAuthorizationSuccess(ts, u, tokenCount, userCount, "authentik@example.com", "Authentik Test User", "7d5e3b6c-4f2a-1b8e-9d3c-5a2f8e1b4c7d", "https://authentik.example.com")
}

func (ts *AuthentikTestSuite) TestSignupExternalAuthentikDisableSignupErrorWhenNoUser() {
	ts.Config.DisableSignup = true
	tokenCount, userCount := 0, 0
	code := "authcode"
	server := AuthentikTestSignupSetup(ts, &tokenCount, &userCount, code, authentikUser)
	defer server.Close()

	u := performAuthorization(ts, "authentik", code, "")

	assertAuthorizationFailure(ts, u, "Signups not allowed for this instance", "access_denied", "authentik@example.com")
}

func (ts *AuthentikTestSuite) TestSignupExternalAuthentikDisableSignupErrorWhenNoEmail() {
	ts.Config.DisableSignup = true
	tokenCount, userCount := 0, 0
	code := "authcode"
	server := AuthentikTestSignupSetup(ts, &tokenCount, &userCount, code, authentikUserNoEmail)
	defer server.Close()

	u := performAuthorization(ts, "authentik", code, "")

	assertAuthorizationFailure(ts, u, "Error getting user email from external provider", "server_error", "")
}

func (ts *AuthentikTestSuite) TestSignupExternalAuthentikDisableSignupSuccessWithPrimaryEmail() {
	ts.Config.DisableSignup = true

	ts.createUser("7d5e3b6c-4f2a-1b8e-9d3c-5a2f8e1b4c7d", "authentik@example.com", "Authentik Test User", "https://authentik.example.com", "")

	tokenCount, userCount := 0, 0
	code := "authcode"
	server := AuthentikTestSignupSetup(ts, &tokenCount, &userCount, code, authentikUser)
	defer server.Close()

	u := performAuthorization(ts, "authentik", code, "")

	assertAuthorizationSuccess(ts, u, tokenCount, userCount, "authentik@example.com", "Authentik Test User", "7d5e3b6c-4f2a-1b8e-9d3c-5a2f8e1b4c7d", "https://authentik.example.com")
}

func (ts *AuthentikTestSuite) TestInviteTokenExternalAuthentikSuccessWhenMatchingToken() {
	// name and avatar should be populated from Authentik API
	ts.createUser("7d5e3b6c-4f2a-1b8e-9d3c-5a2f8e1b4c7d", "authentik@example.com", "", "", "invite_token")

	tokenCount, userCount := 0, 0
	code := "authcode"
	server := AuthentikTestSignupSetup(ts, &tokenCount, &userCount, code, authentikUser)
	defer server.Close()

	u := performAuthorization(ts, "authentik", code, "invite_token")

	assertAuthorizationSuccess(ts, u, tokenCount, userCount, "authentik@example.com", "Authentik Test User", "7d5e3b6c-4f2a-1b8e-9d3c-5a2f8e1b4c7d", "https://authentik.example.com")
}

func (ts *AuthentikTestSuite) TestInviteTokenExternalAuthentikErrorWhenNoMatchingToken() {
	tokenCount, userCount := 0, 0
	code := "authcode"
	user := `{"iss":"https://authentik.example.com","sub":"7d5e3b6c-4f2a-1b8e-9d3c-5a2f8e1b4c7d","aud":"authentik-client-id","exp":1234567890,"iat":1234567890,"auth_time":1234567890,"nonce":"test-nonce","acr":"goauthentik.io/providers/oauth2/default","amr":["goauthentik.io/providers/oauth2/access_token"],"session_state":"test-session","email":"authentik@example.com","email_verified":true,"name":"Authentik Test User","given_name":"Authentik","family_name":"Test User","preferred_username":"authentikuser"}`
	server := AuthentikTestSignupSetup(ts, &tokenCount, &userCount, code, user)
	defer server.Close()

	w := performAuthorizationRequest(ts, "authentik", "invite_token")
	ts.Require().Equal(http.StatusNotFound, w.Code)
}

func (ts *AuthentikTestSuite) TestInviteTokenExternalAuthentikErrorWhenEmailDoesntMatch() {
	ts.createUser("7d5e3b6c-4f2a-1b8e-9d3c-5a2f8e1b4c7d", "authentik@example.com", "", "", "invite_token")

	tokenCount, userCount := 0, 0
	code := "authcode"
	server := AuthentikTestSignupSetup(ts, &tokenCount, &userCount, code, authentikUserWrongEmail)
	defer server.Close()

	u := performAuthorization(ts, "authentik", code, "invite_token")

	assertAuthorizationFailure(ts, u, "Invited email does not match emails from external provider", "invalid_request", "")
}

func (ts *AuthentikTestSuite) TestSignupExternalAuthentikErrorWhenUserBanned() {
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

func (ts *AuthentikTestSuite) TestSignupExternalAuthentikWithCustomClaims() {
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

// Concrete test functions
func (ts *AuthentikTestSuite) createUser(providerId string, email string, name string, imageURL string, inviteToken string) *models.User {
	return ts.createUserWithMetadata(providerId, email, name, imageURL, inviteToken, nil)
}

func (ts *AuthentikTestSuite) createUserWithMetadata(providerId string, email string, name string, imageURL string, inviteToken string, metadata map[string]interface{}) *models.User {
	user := &models.User{
		Email:     email,
		UserMetaData: metadata,
	}
	
	if name != "" {
		user.UserMetaData = map[string]interface{}{
			"full_name": name,
		}
	}
	
	if imageURL != "" {
		if user.UserMetaData == nil {
			user.UserMetaData = make(map[string]interface{})
		}
		user.UserMetaData["avatar_url"] = imageURL
	}

	if inviteToken != "" {
		user.ConfirmationToken = inviteToken
	}

	err := ts.API.db.Create(user)
	require.NoError(ts.T(), err)

	if providerId != "" {
		identity := &models.Identity{
			UserID:     user.ID,
			Provider:   "authentik",
			ProviderID: providerId,
		}
		err = ts.API.db.Create(identity)
		require.NoError(ts.T(), err)
	}

	return user
}

func performAuthorizationRequest(ts *AuthentikTestSuite, provider string, inviteToken string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("http://localhost/authorize?provider=%s&invite_token=%s", provider, inviteToken), nil)
	w := httptest.NewRecorder()
	ts.API.handler.ServeHTTP(w, req)
	return w
}

func performAuthorization(ts *AuthentikTestSuite, provider string, code string, inviteToken string) *url.URL {
	w := performAuthorizationRequest(ts, provider, inviteToken)
	ts.Require().Equal(http.StatusFound, w.Code)
	u, err := url.Parse(w.Header().Get("Location"))
	ts.Require().NoError(err, "redirect url parse failed")

	state := u.Query().Get("state")
	req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("http://localhost/callback?provider=%s&state=%s&code=%s", provider, state, code), nil)
	w = httptest.NewRecorder()
	ts.API.handler.ServeHTTP(w, req)
	ts.Require().Equal(http.StatusFound, w.Code)
	u, err = url.Parse(w.Header().Get("Location"))
	ts.Require().NoError(err, "redirect url parse failed")

	return u
}

func assertAuthorizationSuccess(ts *AuthentikTestSuite, u *url.URL, tokenCount, userCount int, email, name, providerId, avatarURL string) {
	// ensure that we got the right number of providers
	ts.Require().Equal(1, tokenCount)
	ts.Require().Equal(1, userCount)

	v, err := url.ParseQuery(u.Fragment)
	ts.Require().NoError(err)

	ts.Require().NotEmpty(v.Get("access_token"))
	ts.Require().NotEmpty(v.Get("refresh_token"))
	ts.Require().NotEmpty(v.Get("expires_in"))
	ts.Require().Equal("bearer", v.Get("token_type"))

	ts.Require().Equal("authentik_token", v.Get("provider_token"))
	ts.Require().Equal("authentik_refresh_token", v.Get("provider_refresh_token"))

	// Ensure user exists
	user, err := models.FindUserByEmailAndAudience(ts.API.db, email, ts.Config.JWT.Aud)
	ts.Require().NoError(err)
	ts.Require().Equal(email, user.GetEmail())
	
	if name != "" {
		ts.Require().Equal(name, user.UserMetaData["full_name"])
	}
	
	if avatarURL != "" {
		ts.Require().Equal(avatarURL, user.UserMetaData["avatar_url"])
	}

	// Check that identity was created/updated
	identities, err := models.FindIdentitiesByUserID(ts.API.db, user.ID)
	ts.Require().NoError(err)
	
	var found bool
	for _, identity := range identities {
		if identity.Provider == "authentik" && identity.ProviderID == providerId {
			found = true
			break
		}
	}
	ts.Require().True(found, "authentik identity not found for user")
}

func assertAuthorizationFailure(ts *AuthentikTestSuite, u *url.URL, errorDescription, error, errorCode string) {
	v, err := url.ParseQuery(u.Fragment)
	ts.Require().NoError(err)
	ts.Require().Equal(errorDescription, v.Get("error_description"))
	ts.Require().Equal(error, v.Get("error"))
	if errorCode != "" {
		ts.Require().Equal(errorCode, v.Get("error_code"))
	}
}