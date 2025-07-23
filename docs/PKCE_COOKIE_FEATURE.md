# PKCE Flow Cookie Feature

This document describes the new feature that allows setting cookies in PKCE flow for OAuth authentication.

## Overview

By default, when using PKCE (Proof Key for Code Exchange) flow, GoTrue returns only an authorization code to the client application, which must then exchange it for tokens via a separate request. This feature adds an option to set authentication cookies directly during the callback, simplifying client implementation.

## Configuration

Enable this feature by setting the following environment variable:

```bash
GOTRUE_SECURITY_PKCE_FLOW_COOKIE_ENABLED=true
```

## Cookie Configuration

When enabled, the feature uses the standard GoTrue cookie configuration:

```bash
GOTRUE_COOKIE_NAME=sb-auth-token        # Cookie name prefix
GOTRUE_COOKIE_DOMAIN=.example.com       # Cookie domain for cross-subdomain sharing
GOTRUE_COOKIE_SECURE=true               # Secure flag (HTTPS only)
GOTRUE_COOKIE_SAMESITE=lax              # SameSite attribute (strict/lax/none)
```

## How It Works

1. User initiates OAuth authentication with PKCE
2. After successful authentication at the provider
3. Provider redirects back to `/auth/v1/callback`
4. GoTrue validates the authorization code
5. If `PKCE_FLOW_COOKIE_ENABLED` is true:
   - Issues refresh and access tokens
   - Sets authentication cookies
   - Still returns the authorization code in the redirect
6. Client receives both:
   - Authorization code (for standard PKCE flow compatibility)
   - Authentication cookies (for immediate session access)

## Security Considerations

- **PKCE Security**: The authorization code is still validated with the code verifier
- **Cookie Security**: Cookies are set with HttpOnly, Secure, and SameSite attributes
- **Backward Compatibility**: Clients can still exchange the code if needed
- **Default Behavior**: Feature is disabled by default to maintain standard PKCE security model

## Use Cases

This feature is particularly useful when:
- Client applications need immediate session access without additional requests
- Simplifying authentication flow in trusted environments
- Working with legacy clients that expect cookie-based sessions

## Example Implementation

```go
// In external.go
if config.Security.PKCEFlowCookieEnabled && token != nil {
    if err := setCookieTokens(config, token, w); err != nil {
        // Log error but don't fail the request
        logrus.WithError(err).Warn("Failed to set cookie tokens in PKCE flow")
    }
}
```

## Migration Guide

To enable this feature in an existing deployment:

1. Set `GOTRUE_SECURITY_PKCE_FLOW_COOKIE_ENABLED=true`
2. Ensure cookie configuration is properly set
3. Restart the GoTrue service
4. No client-side changes required (cookies are set automatically)

## Notes

- This feature is specific to OAuth providers using PKCE flow
- Regular OAuth flows (without PKCE) are not affected
- The feature respects all existing cookie configuration options