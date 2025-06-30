package provider

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/supabase/auth/internal/conf"
	"golang.org/x/oauth2"
)

// Authentik scopes
const (
	defaultAuthentikAuthBase = "application/o"
)

// AuthentikProvider represents an Authentik OIDC provider
type AuthentikProvider struct {
	*oauth2.Config
	Host string
}

type authentikUser struct {
	Iss           string                 `json:"iss"`
	Sub           string                 `json:"sub"`
	Aud           interface{}            `json:"aud"`
	Exp           int                    `json:"exp"`
	Iat           int                    `json:"iat"`
	AuthTime      int                    `json:"auth_time,omitempty"`
	Nonce         string                 `json:"nonce,omitempty"`
	ACR           string                 `json:"acr"`
	AMR           []string               `json:"amr"`
	SessionState  string                 `json:"session_state,omitempty"`
	Email         string                 `json:"email"`
	EmailVerified bool                   `json:"email_verified"`
	Name          string                 `json:"name"`
	GivenName     string                 `json:"given_name"`
	FamilyName    string                 `json:"family_name"`
	PreferredUsername string             `json:"preferred_username"`
	CustomClaims  map[string]interface{} `json:"-"`
}

// UnmarshalJSON implements a custom unmarshaler to handle both known and unknown claims
func (u *authentikUser) UnmarshalJSON(data []byte) error {
	type Alias authentikUser
	aux := &struct {
		*Alias
	}{
		Alias: (*Alias)(u),
	}
	
	// First unmarshal into the known fields
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}
	
	// Then unmarshal into a map to capture custom claims
	var rawClaims map[string]interface{}
	if err := json.Unmarshal(data, &rawClaims); err != nil {
		return err
	}
	
	// Remove known claims
	knownClaims := []string{
		"iss", "sub", "aud", "exp", "iat", "auth_time", "nonce", 
		"acr", "amr", "session_state", "email", "email_verified", 
		"name", "given_name", "family_name", "preferred_username",
	}
	
	u.CustomClaims = make(map[string]interface{})
	for k, v := range rawClaims {
		isKnown := false
		for _, known := range knownClaims {
			if k == known {
				isKnown = true
				break
			}
		}
		if !isKnown {
			u.CustomClaims[k] = v
		}
	}
	
	return nil
}

// NewAuthentikProvider creates a Authentik OIDC provider
func NewAuthentikProvider(ext conf.OAuthProviderConfiguration, scopes string) (OAuthProvider, error) {
	if err := ext.ValidateOAuth(); err != nil {
		return nil, err
	}

	// For Authentik, we need to extract the base OAuth path
	// The URL format is: https://auth.example.com/application/o/app-slug
	// But the endpoints are at: https://auth.example.com/application/o/
	baseURL := ext.URL
	
	// Extract the base URL (remove app slug from the end)
	if idx := strings.LastIndex(ext.URL, "/o/"); idx != -1 {
		// Find everything after /o/
		afterO := ext.URL[idx+3:]
		// If there's a slash after /o/, keep everything including the slash
		// Otherwise, we need to add /o/ back
		if strings.Contains(afterO, "/") {
			// URL already has proper format
			baseURL = ext.URL
		} else {
			// URL ends with app slug, remove it
			baseURL = ext.URL[:idx+3]
		}
	}
	
	// Ensure the base URL ends with a trailing slash
	if !strings.HasSuffix(baseURL, "/") {
		baseURL += "/"
	}

	oauthScopes := []string{"openid", "profile", "email"}
	if scopes != "" {
		oauthScopes = append(oauthScopes, strings.Split(scopes, ",")...)
	}

	return &AuthentikProvider{
		Config: &oauth2.Config{
			ClientID:     ext.ClientID[0],
			ClientSecret: ext.Secret,
			Endpoint: oauth2.Endpoint{
				AuthURL:  baseURL + "authorize/",
				TokenURL: baseURL + "token/",
			},
			Scopes:      oauthScopes,
			RedirectURL: ext.RedirectURI,
		},
		Host: baseURL,
	}, nil
}

// GetOAuthToken exchanges an authorization code for an OAuth token
func (g AuthentikProvider) GetOAuthToken(code string) (*oauth2.Token, error) {
	return g.Exchange(context.Background(), code)
}

// GetUserData fetches user data from Authentik using the userinfo endpoint
func (g AuthentikProvider) GetUserData(ctx context.Context, tok *oauth2.Token) (*UserProvidedData, error) {
	var u authentikUser

	// Authentik userinfo endpoint
	userInfoURL := g.Host + "userinfo/"
	
	if err := makeRequest(ctx, tok, g.Config, userInfoURL, &u); err != nil {
		return nil, err
	}
	

	data := &UserProvidedData{}
	
	// Create claims map
	claims := map[string]interface{}{
		"iss":              u.Iss,
		"sub":              u.Sub,
		"aud":              u.Aud,
		"exp":              u.Exp,
		"iat":              u.Iat,
		"name":             u.Name,
		"given_name":       u.GivenName,
		"family_name":      u.FamilyName,
		"preferred_username": u.PreferredUsername,
		"email":            u.Email,
		"email_verified":   u.EmailVerified,
		"provider":         "authentik",
		"providers":        []string{"authentik"},
	}

	// Add optional claims if present
	if u.AuthTime != 0 {
		claims["auth_time"] = u.AuthTime
	}
	if u.Nonce != "" {
		claims["nonce"] = u.Nonce
	}
	if u.ACR != "" {
		claims["acr"] = u.ACR
	}
	if len(u.AMR) > 0 {
		claims["amr"] = u.AMR
	}
	if u.SessionState != "" {
		claims["session_state"] = u.SessionState
	}

	// Add custom claims
	if len(u.CustomClaims) > 0 {
		claims["custom_claims"] = u.CustomClaims
	}

	// Format provider id
	// Authentik subjects are usually UUIDs, so we use them directly
	claims["provider_id"] = u.Sub

	data.Metadata = &Claims{
		Issuer:        u.Iss,
		Subject:       u.Sub,
		Name:          u.Name,
		GivenName:     u.GivenName,
		FamilyName:    u.FamilyName,
		PreferredUsername: u.PreferredUsername,
		Email:         u.Email,
		EmailVerified: u.EmailVerified,
		ProviderId:    u.Sub,  // Add provider_id for compatibility

		// Store all claims for flexibility
		CustomClaims: claims,
	}

	// Set emails
	if u.Email != "" {
		data.Emails = []Email{
			{
				Email:    u.Email,
				Verified: u.EmailVerified,
				Primary:  true,
			},
		}
	}

	return data, nil
}