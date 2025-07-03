# Changelog - Authentik OIDC Provider Support

## [Fork] - 2025-07-03

### Added
- **Authentik OIDC Provider Support**
  - New provider implementation in `/internal/api/provider/authentik.go`
  - Full OAuth2/OIDC flow support with PKCE
  - Flexible claim mapping for user data
  - Custom claims preservation in user metadata
  - Multi-subdomain cookie support

### Configuration
- Added `Authentik` field to `ProviderConfiguration` struct
- New environment variables:
  - `GOTRUE_EXTERNAL_AUTHENTIK_ENABLED`
  - `GOTRUE_EXTERNAL_AUTHENTIK_CLIENT_ID`
  - `GOTRUE_EXTERNAL_AUTHENTIK_SECRET`
  - `GOTRUE_EXTERNAL_AUTHENTIK_REDIRECT_URI`
  - `GOTRUE_EXTERNAL_AUTHENTIK_URL`

### Testing
- Comprehensive test suite in `/internal/api/external_authentik_test.go`
- Tests cover various claim formats and edge cases
- Integrated with existing `ExternalTestSuite`

### Documentation
- Provider documentation in `/docs/providers/authentik.md`
- Japanese documentation in `/docs/providers/authentik_ja.md`
- Implementation details in `/docs/AUTHENTIK_IMPLEMENTATION.md`
- Updated README.md with Authentik configuration section

### Fixed
- PKCE flow issues with multi-subdomain deployments
- Cookie domain configuration for cross-subdomain authentication
- Redirect URI handling for proper OAuth2 flow

## Implementation Notes

### Based on Keycloak Pattern
The Authentik implementation follows the pattern established by the Keycloak provider, as both are flexible OIDC providers requiring similar configuration approaches.

### Key Features
1. **Flexible URL Configuration**: Supports Authentik's application-specific OAuth endpoints
2. **Comprehensive Claim Mapping**: Handles standard OIDC claims plus custom attributes
3. **PKCE Support**: Full support for enhanced security flows
4. **Multi-domain Ready**: Proper cookie configuration for complex deployments

### Compatibility
- Tested with Authentik 2023.x and 2024.x versions
- Compatible with Supabase Auth v2.149.0 and later
- Supports both cloud and self-hosted Supabase deployments

## Upgrade Guide

To enable Authentik support in your existing Supabase Auth deployment:

1. Update to this fork or wait for official support
2. Configure Authentik application with OAuth2/OIDC provider
3. Set required environment variables
4. Update redirect URI in both Authentik and Supabase configuration
5. Test authentication flow

## Known Issues

- Phone number claim (`phone_number`) requires proper scope configuration in Authentik
- Custom claims must be configured in Authentik to appear in user metadata
- Cookie domain must be properly set for multi-subdomain deployments

## Contributing

If you encounter issues or have improvements:
1. Check existing issues in the original repository
2. Test with debug logging enabled (`GOTRUE_LOG_LEVEL=debug`)
3. Provide complete configuration details (excluding secrets)
4. Include relevant logs and error messages

## Acknowledgments

- Based on the excellent Keycloak implementation
- Thanks to the Supabase team for the extensible provider architecture
- Community feedback from issue #451 helped shape this implementation