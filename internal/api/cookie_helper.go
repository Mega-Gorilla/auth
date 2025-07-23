package api

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/supabase/auth/internal/conf"
)

// setCookieTokens sets authentication tokens as HTTP cookies
func setCookieTokens(config *conf.GlobalConfiguration, token *AccessTokenResponse, w http.ResponseWriter) error {
	// Get cookie configuration from environment variables
	cookieName := os.Getenv("GOTRUE_COOKIE_NAME")
	if cookieName == "" {
		// Default cookie name based on the auth URL
		cookieName = "sb-auth-token"
	}

	cookieDomain := os.Getenv("GOTRUE_COOKIE_DOMAIN")
	cookieSecure := os.Getenv("GOTRUE_COOKIE_SECURE") == "true"
	cookieSameSite := http.SameSiteLaxMode

	// Parse SameSite setting
	sameSiteStr := os.Getenv("GOTRUE_COOKIE_SAMESITE")
	switch strings.ToLower(sameSiteStr) {
	case "strict":
		cookieSameSite = http.SameSiteStrictMode
	case "none":
		cookieSameSite = http.SameSiteNoneMode
	case "lax", "":
		cookieSameSite = http.SameSiteLaxMode
	}

	// Create session data
	sessionData := map[string]interface{}{
		"access_token":  token.Token,
		"token_type":    token.TokenType,
		"expires_in":    token.ExpiresIn,
		"expires_at":    token.ExpiresAt,
		"refresh_token": token.RefreshToken,
		"user":          token.User,
	}

	// Encode session data as base64
	sessionJSON, err := json.Marshal(sessionData)
	if err != nil {
		return fmt.Errorf("failed to marshal session data: %w", err)
	}
	
	sessionString := base64.URLEncoding.EncodeToString(sessionJSON)

	// Split cookie if it's too large (4KB limit)
	const maxCookieSize = 3900 // Leave some margin
	chunks := []string{}
	
	for i := 0; i < len(sessionString); i += maxCookieSize {
		end := i + maxCookieSize
		if end > len(sessionString) {
			end = len(sessionString)
		}
		chunks = append(chunks, sessionString[i:end])
	}

	// Set cookies
	for i, chunk := range chunks {
		cookieNameWithIndex := cookieName
		if i > 0 {
			cookieNameWithIndex = fmt.Sprintf("%s.%d", cookieName, i)
		}

		http.SetCookie(w, &http.Cookie{
			Name:     cookieNameWithIndex,
			Value:    chunk,
			Domain:   cookieDomain,
			Path:     "/",
			MaxAge:   60 * 60 * 24 * 365, // 1 year
			Secure:   cookieSecure,
			HttpOnly: true,
			SameSite: cookieSameSite,
		})
	}

	return nil
}

// clearCookieTokens clears authentication cookies
func clearCookieTokens(config *conf.GlobalConfiguration, w http.ResponseWriter) {
	cookieName := os.Getenv("GOTRUE_COOKIE_NAME")
	if cookieName == "" {
		cookieName = "sb-auth-token"
	}
	
	cookieDomain := os.Getenv("GOTRUE_COOKIE_DOMAIN")

	// Clear main cookie and potential chunks
	for i := 0; i < 10; i++ { // Assume max 10 chunks
		cookieNameWithIndex := cookieName
		if i > 0 {
			cookieNameWithIndex = fmt.Sprintf("%s.%d", cookieName, i)
		}

		http.SetCookie(w, &http.Cookie{
			Name:     cookieNameWithIndex,
			Value:    "",
			Domain:   cookieDomain,
			Path:     "/",
			MaxAge:   -1, // Delete cookie
			Secure:   true,
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
		})
	}
}