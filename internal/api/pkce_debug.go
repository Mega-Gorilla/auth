package api

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/sirupsen/logrus"
	"github.com/supabase/auth/internal/conf"
)

// debugPKCEFlow logs PKCE flow details for debugging
func debugPKCEFlow(r *http.Request, stage string, data map[string]interface{}) {
	if logrus.GetLevel() < logrus.DebugLevel {
		return
	}

	log := logrus.WithFields(logrus.Fields{
		"stage":      stage,
		"method":     r.Method,
		"path":       r.URL.Path,
		"host":       r.Host,
		"referer":    r.Header.Get("Referer"),
		"user_agent": r.Header.Get("User-Agent"),
	})

	// Log cookie information
	cookies := r.Cookies()
	cookieInfo := make([]string, 0, len(cookies))
	for _, cookie := range cookies {
		// Mask sensitive values
		value := cookie.Value
		if len(value) > 10 {
			value = value[:10] + "..."
		}
		cookieInfo = append(cookieInfo, fmt.Sprintf("%s=%s (domain=%s, path=%s)", 
			cookie.Name, value, cookie.Domain, cookie.Path))
	}
	if len(cookieInfo) > 0 {
		log = log.WithField("cookies", strings.Join(cookieInfo, "; "))
	}

	// Log X-Forwarded headers
	if xfh := r.Header.Get("X-Forwarded-Host"); xfh != "" {
		log = log.WithField("x_forwarded_host", xfh)
	}
	if xfp := r.Header.Get("X-Forwarded-Proto"); xfp != "" {
		log = log.WithField("x_forwarded_proto", xfp)
	}

	// Add custom data
	for k, v := range data {
		log = log.WithField(k, v)
	}

	log.Debug("PKCE flow debug")
}

// getCookieDomain determines the appropriate cookie domain
func getCookieDomain(r *http.Request, config *conf.GlobalConfiguration) string {
	// First check if cookie domain is explicitly configured
	if config.Cookie.Domain != "" {
		return config.Cookie.Domain
	}

	// Check X-Forwarded-Host header (when behind proxy)
	if xfh := r.Header.Get("X-Forwarded-Host"); xfh != "" {
		// Extract domain from forwarded host
		host := strings.Split(xfh, ":")[0] // Remove port if present
		
		// For subdomains, we want to set the parent domain
		// e.g., db.compass-pharmacy.jp -> .compass-pharmacy.jp
		parts := strings.Split(host, ".")
		if len(parts) > 2 {
			// Return parent domain with leading dot for subdomain sharing
			return "." + strings.Join(parts[len(parts)-2:], ".")
		}
		return host
	}

	// Fallback to request host
	host := strings.Split(r.Host, ":")[0]
	return host
}

// setPKCECookie sets a cookie with proper domain handling for PKCE flow
func setPKCECookie(w http.ResponseWriter, r *http.Request, config *conf.GlobalConfiguration, name, value string) {
	domain := getCookieDomain(r, config)
	
	cookie := &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		Domain:   domain,
		HttpOnly: true,
		Secure:   config.Cookie.Secure,
		SameSite: http.SameSite(config.Cookie.SameSite),
		MaxAge:   300, // 5 minutes for PKCE flow
	}

	debugPKCEFlow(r, "set_cookie", map[string]interface{}{
		"cookie_name":   name,
		"cookie_domain": domain,
		"cookie_secure": cookie.Secure,
		"cookie_samesite": cookie.SameSite,
	})

	http.SetCookie(w, cookie)
}

// findPKCECookie attempts to find a PKCE-related cookie with various name patterns
func findPKCECookie(r *http.Request, baseName string) *http.Cookie {
	// Try different cookie name patterns
	patterns := []string{
		baseName,
		"sb-" + baseName,
		"sb-db-auth-token-" + baseName,
		"sb-auth-token-" + baseName,
	}

	cookies := r.Cookies()
	debugPKCEFlow(r, "find_cookie", map[string]interface{}{
		"searching_for": baseName,
		"total_cookies": len(cookies),
		"patterns": patterns,
	})

	for _, pattern := range patterns {
		for _, cookie := range cookies {
			if cookie.Name == pattern {
				debugPKCEFlow(r, "found_cookie", map[string]interface{}{
					"cookie_name": cookie.Name,
					"cookie_domain": cookie.Domain,
				})
				return cookie
			}
		}
	}

	debugPKCEFlow(r, "cookie_not_found", map[string]interface{}{
		"searched_patterns": patterns,
	})
	return nil
}