# Authentik OIDC Provider

This document describes how to configure Supabase Auth to use Authentik as an OIDC (OpenID Connect) provider for authentication.

## Overview

Authentik is an open-source Identity Provider that supports OIDC, SAML, and other authentication protocols. This integration allows users to authenticate with Supabase using their Authentik credentials.

## Prerequisites

- A running Authentik instance
- Administrative access to Authentik
- Supabase Auth instance (self-hosted or cloud)

## Authentik Configuration

### 1. Create an OAuth2/OpenID Provider

1. Log in to your Authentik admin interface
2. Navigate to **Applications** → **Providers**
3. Click **Create** and select **OAuth2/OpenID Provider**
4. Configure the provider with the following settings:
   - **Name**: Choose a descriptive name (e.g., "Supabase Auth")
   - **Authorization flow**: Select your preferred flow (implicit or authorization code)
   - **Client type**: Confidential
   - **Client ID**: Auto-generated or custom (save this value)
   - **Client Secret**: Auto-generated (save this value)
   - **Redirect URIs**: `https://your-supabase-domain/auth/v1/callback`

### 2. Create an Application

1. Navigate to **Applications** → **Applications**
2. Click **Create**
3. Configure the application:
   - **Name**: Choose a descriptive name (e.g., "Supabase")
   - **Slug**: This will be part of your OAuth URL (e.g., "supabase")
   - **Provider**: Select the provider created in step 1
   - **UI settings**: Configure as needed

### 3. Note the OAuth Endpoints

After creating the application, note the following URLs:
- **Authorization URL**: `https://your-authentik-domain/application/o/authorize/`
- **Token URL**: `https://your-authentik-domain/application/o/token/`
- **User Info URL**: `https://your-authentik-domain/application/o/userinfo/`
- **Application URL**: `https://your-authentik-domain/application/o/{slug}/`

## Supabase Auth Configuration

### Environment Variables

Add the following environment variables to your Supabase Auth configuration:

```bash
# Enable Authentik provider
GOTRUE_EXTERNAL_AUTHENTIK_ENABLED=true

# Authentik OAuth credentials
GOTRUE_EXTERNAL_AUTHENTIK_CLIENT_ID=your_client_id
GOTRUE_EXTERNAL_AUTHENTIK_SECRET=your_client_secret

# Redirect URI (must match Authentik configuration)
GOTRUE_EXTERNAL_AUTHENTIK_REDIRECT_URI=https://your-supabase-domain/auth/v1/callback

# Authentik Application URL
# Format: https://your-authentik-domain/application/o/{slug}
GOTRUE_EXTERNAL_AUTHENTIK_URL=https://your-authentik-domain/application/o/supabase
```

### Docker Compose Configuration (Self-hosted)

If using Docker Compose, add these environment variables to your auth service:

```yaml
services:
  auth:
    environment:
      GOTRUE_EXTERNAL_AUTHENTIK_ENABLED: ${GOTRUE_EXTERNAL_AUTHENTIK_ENABLED}
      GOTRUE_EXTERNAL_AUTHENTIK_CLIENT_ID: ${GOTRUE_EXTERNAL_AUTHENTIK_CLIENT_ID}
      GOTRUE_EXTERNAL_AUTHENTIK_SECRET: ${GOTRUE_EXTERNAL_AUTHENTIK_SECRET}
      GOTRUE_EXTERNAL_AUTHENTIK_REDIRECT_URI: ${GOTRUE_EXTERNAL_AUTHENTIK_REDIRECT_URI}
      GOTRUE_EXTERNAL_AUTHENTIK_URL: ${GOTRUE_EXTERNAL_AUTHENTIK_URL}
```

## Usage

### Initiating Authentication

To authenticate users with Authentik, redirect them to:

```
https://your-supabase-domain/auth/v1/authorize?provider=authentik
```

### JavaScript Client Example

Using the Supabase JavaScript client:

```javascript
import { createClient } from '@supabase/supabase-js'

const supabase = createClient(SUPABASE_URL, SUPABASE_ANON_KEY)

// Sign in with Authentik
const { data, error } = await supabase.auth.signInWithOAuth({
  provider: 'authentik',
  options: {
    redirectTo: 'https://your-app.com/auth/callback'
  }
})
```

### PKCE Flow Support

The Authentik provider supports PKCE (Proof Key for Code Exchange) for enhanced security. The client SDK will automatically handle PKCE when available.

## User Data Mapping

The Authentik provider maps the following user data:

| Authentik Claim | Supabase User Field |
|----------------|-------------------|
| `sub` | `id` (in identity) |
| `email` | `email` |
| `email_verified` | `email_confirmed_at` |
| `name` | `user_metadata.full_name` |
| `given_name` | `user_metadata.first_name` |
| `family_name` | `user_metadata.last_name` |
| `nickname` | `user_metadata.username` |
| `preferred_username` | `user_metadata.preferred_username` |
| `picture` | `user_metadata.avatar_url` |
| `phone_number` | `user_metadata.phone` |

Additional claims from Authentik are stored in `user_metadata`.

## Custom Scopes

By default, the following scopes are requested:
- `openid`
- `profile`
- `email`
- `phone`

You can request additional scopes by passing them in the authorization URL:

```
https://your-supabase-domain/auth/v1/authorize?provider=authentik&scopes=openid+profile+email+custom_scope
```

## Troubleshooting

### Common Issues

1. **"Redirect URI Error"**
   - Ensure the redirect URI in Authentik matches exactly with `GOTRUE_EXTERNAL_AUTHENTIK_REDIRECT_URI`
   - Check that the URI includes the full path: `/auth/v1/callback`

2. **"flow_state_not_found" Error**
   - This typically occurs when the PKCE flow is interrupted
   - Ensure cookies are enabled and not blocked by browser settings
   - Check that cookie domain settings allow sharing between subdomains if applicable

3. **Missing User Data**
   - Verify that the requested scopes are configured in Authentik
   - Check that the user has the required attributes populated in Authentik
   - Some claims (like `phone_number`) may require additional configuration in Authentik

### Debug Mode

To enable debug logging for troubleshooting:

```bash
GOTRUE_LOG_LEVEL=debug
```

## Security Considerations

1. **Always use HTTPS** for production deployments
2. **Keep client secrets secure** - never expose them in client-side code
3. **Configure appropriate redirect URIs** to prevent redirect attacks
4. **Use PKCE** when possible (automatically handled by Supabase client SDKs)
5. **Regularly rotate client secrets** in both Authentik and Supabase

## Advanced Configuration

### Custom Claims

Authentik allows you to add custom claims to the ID token. These will be available in the user's `user_metadata` in Supabase.

### Group Mapping

If you need to map Authentik groups to Supabase roles, you can:
1. Configure Authentik to include group information in claims
2. Use Supabase Auth Hooks to process these claims and assign appropriate roles

### Multi-factor Authentication

Authentik's MFA settings will be respected during the authentication flow. Users with MFA enabled in Authentik will need to complete the additional authentication steps before being redirected back to Supabase.

## References

- [Authentik Documentation](https://goauthentik.io/docs/)
- [Supabase Auth Documentation](https://supabase.com/docs/guides/auth)
- [OpenID Connect Specification](https://openid.net/connect/)