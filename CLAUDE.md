# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is Supabase Auth - a JWT-based authentication and user management server written in Go. It provides comprehensive authentication features including email/password, phone, OAuth providers, MFA, SAML SSO, and WebAuthn support.

## Essential Commands

### Development Setup
```bash
# Initial setup - copy environment variables
cp example.env .env

# Start only PostgreSQL for local development
docker-compose -f docker-compose-dev.yml up postgres

# Build the binary
make build

# Run the server locally
./auth

# OR: Run complete Docker development environment with hot reload
cp example.docker.env .env.docker
make dev
```

### Testing
```bash
# Run all tests with coverage
make test

# Run tests in Docker environment
make docker-test

# Run a specific test
go test -v ./internal/api -run TestSignup

# Run tests for a specific package
go test -v ./internal/models/...
```

### Code Quality
```bash
# Format code
make format

# Run static analysis
make vet

# Security vulnerability check
make sec

# All static checks
make static
```

### Database Operations
```bash
# Run migrations (development)
make migrate_dev

# Run migrations manually
./auth migrate

# Create a new migration
# Add SQL files to migrations/ directory following the naming pattern:
# [timestamp]_[description].up.sql and .down.sql
```

## Architecture Overview

### Directory Structure
- `cmd/` - CLI commands (main.go, migrate.go, serve.go)
- `internal/api/` - REST API handlers and middleware
  - Each endpoint has its own file (e.g., signup.go, token.go, verify.go)
  - Middleware in middleware.go
  - Router setup in api.go
- `internal/models/` - Database models and business logic
  - User, Session, RefreshToken, AuditLog models
  - JSON types for flexible data storage
- `internal/conf/` - Configuration management
  - Loads from environment variables (GOTRUE_ prefix)
  - Validates required settings
- `internal/crypto/` - Cryptographic utilities
  - Password hashing (bcrypt/scrypt/argon2)
  - Token generation
- `internal/mailer/` - Email functionality
  - Template-based emails
  - Multiple SMTP provider support
- `internal/hooks/` - Webhook system for extensibility
  - Custom hooks for various auth events
- `migrations/` - PostgreSQL schema migrations

### Key Patterns

1. **Error Handling**: Uses custom error types in `internal/api/errors.go`
   - Always return proper HTTP status codes
   - Include error codes for client handling

2. **Database Access**: Uses database/sql with PostgreSQL
   - Transactions for data consistency
   - Prepared statements for security
   - Connection pooling configured via environment

3. **Authentication Flow**:
   - JWT tokens with configurable expiry
   - Refresh tokens for session management
   - Service role tokens for admin operations
   - Anonymous users support

4. **Provider Integration**: 
   - OAuth providers in `internal/api/provider/`
   - Each provider implements Provider interface
   - Supports 20+ external providers

5. **Middleware Chain**:
   - Request ID generation
   - CORS handling
   - JWT verification
   - Rate limiting
   - Audit logging

### Configuration

Key environment variables (prefix with `GOTRUE_`):
- `JWT_SECRET` - Required for JWT signing
- `DATABASE_URL` - PostgreSQL connection
- `API_EXTERNAL_URL` - Public API URL
- `SITE_URL` - Frontend application URL
- `SMTP_*` - Email configuration
- `EXTERNAL_*_ENABLED` - Enable OAuth providers
- `LOG_LEVEL` - Logging verbosity

### API Endpoints

Public endpoints:
- `POST /signup` - User registration
- `POST /token?grant_type=*` - Token operations
- `POST /verify` - Email/phone verification
- `GET /authorize` - OAuth authorization
- `POST /recover` - Password recovery

Authenticated endpoints (require JWT):
- `GET /user` - Get user details
- `PUT /user` - Update user
- `POST /logout` - Logout
- `GET /factors` - MFA factors

Admin endpoints (require service_role JWT):
- `GET /admin/users` - List users
- `POST /admin/users` - Create user
- `DELETE /admin/users/{id}` - Delete user

### Testing Approach

- Unit tests alongside implementation files
- Test fixtures in `internal/storage/test/`
- Mock external services (email, SMS)
- Database tests use transactions with rollback
- Environment setup in test files using `setupEnv()`

### Security Considerations

- All passwords hashed with configurable algorithm
- JWT tokens signed with HS256
- Refresh token rotation enabled by default
- PKCE required for OAuth flows
- Rate limiting on sensitive endpoints
- Audit logging for security events
- CAPTCHA support for signup/signin