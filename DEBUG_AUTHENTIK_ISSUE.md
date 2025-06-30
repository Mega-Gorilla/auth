# Debugging Authentik OAuth Identity Data Issue

## Problem Description
The identity_data stored in the database is completely different from what we expect from Authentik OAuth provider. The expected data should have Authentik user info but stored data looks like a default/different user.

## Debug Points Added

### 1. In `internal/api/provider/authentik.go`:
- Line 151: Logs the userinfo URL being called
- Line 158-162: Logs raw user data received from Authentik
- Line 165-167: Validates that 'sub' field is present 
- Line 230-232: Logs final metadata and claims being returned

### 2. In `internal/api/provider/provider.go`:
- Line 120-122: Logs raw HTTP response from authentik/userinfo endpoints

### 3. In `internal/api/external.go`:
- Line 291-302: Logs identity data after structs.Map conversion and checks for 'sub' field
- Line 697-706: Logs identity creation with provider, user ID, and data

### 4. In `internal/models/identity.go`:
- Line 43: Logs the identityData received by NewIdentity function

## Key Areas to Check

1. **Raw Response from Authentik**: The debug logs will show exactly what Authentik's userinfo endpoint is returning. Check if:
   - The 'sub' field is present and non-empty
   - The user data matches what you expect from Authentik
   - The response format is correct JSON

2. **Data Transformation**: The logs will show how data is transformed:
   - From authentikUser struct to Claims struct
   - From Claims struct to map via structs.Map()
   - Whether the 'sub' field survives the transformation

3. **Common Issues**:
   - Empty 'sub' field: If Authentik returns an empty subject, it won't be included due to `omitempty` tag
   - Wrong userinfo endpoint: Check if the URL is correct (should be base_url + "userinfo/")
   - Token issues: The access token might not have proper scopes to fetch user info
   - Authentik configuration: The OAuth app in Authentik might not be configured to return user data

## Next Steps

1. Run the OAuth flow with these debug logs enabled
2. Check the logs for:
   ```
   [DEBUG] Authentik userinfo URL: <url>
   [DEBUG] Raw response from <url>: <json>
   [DEBUG] Raw Authentik user data: <struct>
   [DEBUG] Identity data after structs.Map conversion: <map>
   [DEBUG] Creating identity for provider=authentik user=<id> with data: <map>
   ```

3. Compare the raw response with what ends up in the database

4. If the 'sub' field is missing or empty, check:
   - Authentik OAuth app configuration
   - Token scopes (should include "openid", "profile", "email")
   - Whether the user exists in Authentik

## Temporary Fix

Added `ProviderId: u.Sub` to the Claims struct to ensure the provider ID is available even if the struct field mapping has issues.