# Environment Variables Documentation

## ADDITIONAL_REDIRECT_URLS Warning

If you see this warning when starting the auth service:
```
WARN[0000] The "ADDITIONAL_REDIRECT_URLS" variable is not set. Defaulting to a blank string.
```

This is a **harmless warning** that can be safely ignored.

### What is ADDITIONAL_REDIRECT_URLS?

This environment variable is used in Docker-based Supabase deployments to specify additional allowed redirect URLs for OAuth callbacks. It's typically used when you have multiple domains or applications that need to authenticate with the same Supabase instance.

### Why the Warning Appears

The warning appears because the Docker entrypoint script checks for this variable but it's not required for the auth service to function properly. If not set, it defaults to an empty string, which is perfectly fine for single-domain deployments.

### When You Need to Set It

You only need to set `ADDITIONAL_REDIRECT_URLS` if:
- You have multiple domains that need to authenticate (e.g., staging and production)
- You're running multiple applications against the same auth instance
- You need to support different callback URLs for different OAuth providers

### How to Set It (Optional)

If needed, you can set it in your Docker environment:

```bash
ADDITIONAL_REDIRECT_URLS=https://staging.example.com/**,https://app2.example.com/**
```

Or in docker-compose.yml:
```yaml
environment:
  ADDITIONAL_REDIRECT_URLS: "https://staging.example.com/**,https://app2.example.com/**"
```

### For Compass Pharmacy

Since Compass Pharmacy uses a single domain with subdomains handled by the wildcard cookie domain (`.compass-pharmacy.jp`), this variable is not needed and the warning can be ignored.