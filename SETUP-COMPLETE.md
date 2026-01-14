#  Setup Complete - Quick Reference

## Your Questions Answered

### Q: Why do I need a `.env` file when I have `.env.development` and `.env.production`?

**A:** Docker Compose is hardcoded to look for `.env` in your `docker-compose.yml`:

```yaml
api:
  env_file:
    - .env    # Docker expects this file
```

**Solution:** We make `.env` a **symlink** that points to whichever environment you want:
- `.env` → `.env.development` (for local dev)
- `.env` → `.env.production` (for production)

### Q: How do I run production code?

**A:** Simple:
```bash
make prod
```

This automatically:
1. Switches `.env` to point to `.env.production`
2. Runs your app with cloud services (Supabase, Upstash, Resend)

## File Structure

```
healthcare-access-connector-backend/
├── .env                    # Symlink → points to one of below
├── .env.development        # Local config (committed to Git)
├── .env.production         # Production config (committed to Git)
├── docker-compose.yml      # Reads .env
└── Makefile               # Handles everything
```

## Commands You'll Use Daily

### Environment Management
```bash
make env-status      # See which environment is active
make switch-dev      # Point .env → .env.development
make switch-prod     # Point .env → .env.production
```

### Running the App
```bash
make dev            # Development mode (auto-switches env)
make prod           # Production mode (auto-switches env)
make run            # Run with current .env
```

### Database
```bash
make migrate-up     # Run migrations
make migrate-down   # Rollback migration
make migrate-create name=add_users_table
```

### Docker Services
```bash
make docker-up      # Start PostgreSQL, Redis, Mailpit, NATS
make docker-down    # Stop services
make docker-logs    # View logs
make docker-clean   # Stop and remove volumes
```

### Code Quality
```bash
make test           # Run tests
make fmt            # Format code
make lint           # Lint code
make check          # Run all checks
```

## What Each Mode Does

### Development Mode (`make dev`)

```
.env → .env.development

Services:
 PostgreSQL (localhost:5432) - postgres/admin
 Redis (localhost:6379)
 Mailpit (localhost:8025) - Email testing UI
 NATS (localhost:4222)

Features:
 Works offline
 Fast bcrypt (cost=4)
 Debug logging
 Relaxed rate limits
 All emails caught by Mailpit
```

### Production Mode (`make prod`)

```
.env → .env.production

Services:
☁️ Supabase PostgreSQL
☁️ Upstash Redis
☁️ Resend Email
☁️ NATS (if configured)

Features:
 Requires internet
 Secure bcrypt (cost=12)
 Info logging
 Strict rate limits
 Real emails via Resend
```

## First Time Setup Checklist

```bash
# 1. Run setup script
chmod +x scripts/setup-dev.sh
./scripts/setup-dev.sh

# 2. Generate JWT secret
make generate-jwt
# Copy output to .env.development

# 3. Check environment
make env-status
# Should show: .env → .env.development

# 4. Run migrations
make migrate-up

# 5. Start development
make dev
```

## Typical Workflows

### Daily Development

```bash
# Start day
make dev

# Code, test, repeat...
make test

# End day
make docker-down
```

### Testing Production Config Locally

```bash
# Switch to production
make prod

# Test with cloud services
# (requires internet and configured credentials)
```

### Deploying to Render

```bash
# Work on develop branch
git checkout develop
git add .
git commit -m "Add feature"
git push origin develop

# When ready for production
git checkout main
git merge develop
git push origin main  # Triggers Render deployment
```

## Common Errors & Fixes

### Error: "Couldn't find env file: .env"

```bash
# Fix: Create symlink
make switch-dev
```

### Error: "DB_URL is required"

```bash
# Fix: Don't run go directly, use make
make dev   # Not: go run cmd/api/main.go
```

### Error: "connection refused" to database

```bash
# Fix: Start Docker services
make docker-up

# Wait a few seconds, then
make dev
```

### Emails not showing in Mailpit

```bash
# Check Mailpit is running
docker ps | grep mailpit

# Access Mailpit UI
open http://localhost:8025

# Check your .env points to development
make env-status
```

## File Descriptions

| File | Purpose | Committed? |
|------|---------|------------|
| `.env` | Symlink to active config |  No |
| `.env.development` | Local dev config |  Yes |
| `.env.production` | Production template |  Yes |
| `docker-compose.yml` | Local services |  Yes |
| `Makefile` | All commands |  Yes |

## Environment Variables Priority

When the app loads config, it checks in this order:

1. **System environment variables** (highest)
2. **`.env` file** (symlink to .env.development or .env.production)
3. **Code defaults** (lowest)

## Quick Verification

Check everything is set up correctly:

```bash
# 1. Check symlink exists
ls -la .env
# Should show: .env -> .env.development

# 2. Check environment status
make env-status

# 3. Test services
make docker-up
docker ps  # Should show 4 containers running

# 4. Test app
make dev

# 5. Check health
curl http://localhost:8080/health
```

## Getting Help

```bash
make help           # Show all commands
make env-status     # Check current environment

# Read the guides
cat QUICKSTART.md   # Quick start
cat ENVIRONMENT.md  # Environment details
cat DEVELOPMENT.md  # Full development guide
```

## Pro Tips

1. **Always use `make` commands** - They handle env switching automatically
2. **Check your env before running** - `make env-status`
3. **Use `make dev` for daily work** - Sets everything up for you
4. **Stop Docker when done** - `make docker-down` saves resources
5. **Never commit real secrets** - Use placeholders in .env files

## What's Next?

Now you're ready to:
-  Develop offline with `make dev`
-  Test production mode with `make prod`
-  Switch environments easily
-  Deploy to production confidently

