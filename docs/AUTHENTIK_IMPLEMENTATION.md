# Authentik OIDC Provider Implementation

This document describes the technical implementation details of the Authentik OIDC provider in Supabase Auth.

## Implementation Overview

The Authentik provider was implemented following the pattern established by the Keycloak provider, as both are flexible OIDC providers that support custom configurations.

### Key Files

1. **Provider Implementation**: `/internal/api/provider/authentik.go`
   - Main provider logic implementing the `OAuthProvider` interface
   - Handles OAuth2 token exchange and user data retrieval
   - Custom JSON unmarshaling for flexible claim handling

2. **Configuration**: `/internal/conf/configuration.go`
   - Added `Authentik OAuthProviderConfiguration` field to `ProviderConfiguration` struct

3. **Provider Registration**: `/internal/api/external.go`
   - Added case for "authentik" in the `Provider()` function

4. **Tests**: `/internal/api/external_authentik_test.go`
   - Comprehensive test suite using the shared `ExternalTestSuite`

## Technical Details

### OAuth2 Flow

The Authentik provider implements the standard OAuth2 authorization code flow with PKCE support:

1. **Authorization**: User is redirected to Authentik's `/authorize` endpoint
2. **Callback**: Authentik redirects back with an authorization code
3. **Token Exchange**: The code is exchanged for access and ID tokens
4. **User Info**: User data is extracted from the ID token or UserInfo endpoint

### URL Structure

Authentik uses a specific URL pattern for OAuth endpoints:
```
https://authentik.example.com/application/o/{app-slug}/
```

The provider implementation handles this by:
- Accepting the full application URL in configuration
- Automatically constructing the correct endpoints (`/authorize`, `/token`, `/userinfo`)

### User Data Mapping

The provider implements flexible claim mapping to handle various Authentik configurations:

```go
type authentikUser struct {
    Sub               string                 `json:"sub"`
    Name              string                 `json:"name"`
    GivenName         string                 `json:"given_name"`
    FamilyName        string                 `json:"family_name"`
    PreferredUsername string                 `json:"preferred_username"`
    Nickname          string                 `json:"nickname"`
    Email             string                 `json:"email"`
    EmailVerified     bool                   `json:"email_verified"`
    Picture           string                 `json:"picture"`
    Phone             string                 `json:"phone_number"`
    CustomClaims      map[string]interface{} `json:"-"`
}
```

### Custom Claims Handling

The implementation uses a custom `UnmarshalJSON` method to:
1. Extract standard OIDC claims
2. Preserve any additional claims in `CustomClaims`
3. Merge all claims into the user metadata

This allows Authentik administrators to add custom attributes that will be available in Supabase.

## PKCE Flow Support

The implementation fully supports PKCE (Proof Key for Code Exchange) for enhanced security:

### Flow State Management

1. **Creation**: A flow state is created during `/authorize` with:
   - Generated auth_code (UUID)
   - Code challenge from client
   - Code challenge method (S256)

2. **Storage**: Flow states are stored in the database with:
   - User association after successful authentication
   - Provider tokens for later use
   - Expiration tracking

3. **Verification**: During token exchange:
   - Code verifier is validated against stored code challenge
   - Flow state is deleted after successful exchange

### Cookie Configuration

For multi-subdomain deployments, proper cookie configuration is essential:

```bash
GOTRUE_COOKIE_DOMAIN=.example.com
GOTRUE_COOKIE_NAME=sb-auth-token
GOTRUE_COOKIE_SECURE=true
GOTRUE_COOKIE_SAMESITE=lax
```

## Testing

The test suite covers:
- User data extraction from various claim formats
- Email verification status
- Phone number handling
- Custom claim preservation

### Running Tests

```bash
# Run Authentik-specific tests
go test -v ./internal/api -run TestAuthentik

# Run all external provider tests
go test -v ./internal/api -run TestExternal
```

## Configuration Examples

### Basic Configuration

```bash
GOTRUE_EXTERNAL_AUTHENTIK_ENABLED=true
GOTRUE_EXTERNAL_AUTHENTIK_CLIENT_ID=your-client-id
GOTRUE_EXTERNAL_AUTHENTIK_SECRET=your-client-secret
GOTRUE_EXTERNAL_AUTHENTIK_REDIRECT_URI=https://your-auth-domain/auth/v1/callback
GOTRUE_EXTERNAL_AUTHENTIK_URL=https://authentik.example.com/application/o/supabase
```

### Multi-domain Setup

For setups where Supabase Auth runs on a different subdomain:

```bash
# Main application
SITE_URL=https://app.example.com

# Auth service
API_EXTERNAL_URL=https://auth.example.com

# Authentik callback
GOTRUE_EXTERNAL_AUTHENTIK_REDIRECT_URI=https://auth.example.com/auth/v1/callback

# Cookie sharing across subdomains
GOTRUE_COOKIE_DOMAIN=.example.com
```

## Common Issues and Solutions

### 1. Redirect URI Mismatch

**Problem**: "The request fails due to a missing, invalid, or mismatching redirection URI"

**Solution**: Ensure the redirect URI in Authentik exactly matches `GOTRUE_EXTERNAL_AUTHENTIK_REDIRECT_URI`, including protocol and path.

### 2. PKCE Flow State Not Found

**Problem**: "invalid flow state, no valid flow state found"

**Solution**: 
- Check cookie domain configuration
- Ensure cookies are not blocked
- Verify the auth service URL matches the callback URL domain

### 3. Missing User Data

**Problem**: Some user attributes are not available in Supabase

**Solution**:
- Check requested scopes include necessary attributes
- Verify Authentik user has the attributes populated
- Check Authentik scope configuration

## Future Enhancements

Potential improvements for the Authentik provider:

1. **Group Mapping**: Support for mapping Authentik groups to Supabase roles
2. **Dynamic Scope Configuration**: Allow runtime scope configuration
3. **Token Refresh**: Implement refresh token handling for long-lived sessions
4. **Webhook Support**: Integration with Authentik's webhook system for real-time updates

## Contributing

When contributing to the Authentik provider:

1. Follow the existing provider patterns (reference Keycloak implementation)
2. Ensure comprehensive test coverage
3. Update documentation for any new features
4. Test with various Authentik configurations

## References

- [Authentik Documentation](https://goauthentik.io/docs/)
- [OpenID Connect Core](https://openid.net/specs/openid-connect-core-1_0.html)
- [OAuth 2.0 RFC](https://tools.ietf.org/html/rfc6749)
- [PKCE RFC](https://tools.ietf.org/html/rfc7636)