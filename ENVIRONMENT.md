# Environment Management Guide

## Understanding the `.env` Files

### The Three Files

1. **`.env`** - A **symlink** that points to either `.env.development` or `.env.production`
2. **`.env.development`** - Configuration for local development (offline capable)
3. **`.env.production`** - Configuration for production deployment (cloud services)

### Why `.env` is Required

Your `docker-compose.yml` file references `.env`:
```yaml
api:
  env_file:
    - .env    # Docker Compose looks for this file
```

Instead of maintaining a separate `.env` file, we use a **symbolic link** that points to whichever environment you want to use.

## Visual Representation

```
.env --> .env.development    (When in dev mode)
.env --> .env.production     (When in prod mode)
```

Think of `.env` as a shortcut that points to the actual config file.

## How to Use

### First Time Setup

```bash
# Run the setup script
./scripts/setup-dev.sh

# This automatically creates .env -> .env.development
```

### Check Current Environment

```bash
make env-status
```

Output:
```
Current Environment Status:
  .env is a symlink pointing to: .env.development
  → DEVELOPMENT mode
```

### Switching Environments

```bash
# Switch to development
make switch-dev

# Switch to production
make switch-prod

# Or let the commands do it automatically
make dev   # Automatically switches to .env.development
make prod  # Automatically switches to .env.production
```

## Running Different Modes

### Development Mode (Local - Offline)

```bash
make dev
```

What happens:
1. Switches `.env` → `.env.development`
2. Starts Docker services (PostgreSQL, Redis, Mailpit, NATS)
3. Runs the app with local services
4. All emails go to Mailpit (http://localhost:8025)

**No internet needed!** 

### Production Mode (Cloud)

```bash
make prod
```

What happens:
1. Switches `.env` → `.env.production`
2. Runs the app with cloud services:
   - Supabase PostgreSQL
   - Upstash Redis
   - Resend Email
3. **Requires internet** ⚠️

### Run Without Switching

If you want to run with the current `.env` without auto-switching:

```bash
make run
```

## Why Not Just Have Two Files?

You **could** work with just `.env.development` and `.env.production`, but:

1. **Docker Compose expects `.env`** - It's hardcoded in `docker-compose.yml`
2. **Many tools look for `.env`** - It's a standard convention
3. **The symlink is automatic** - Our Makefile handles switching for you

## Troubleshooting

### Error: "Couldn't find env file: .env"

**Cause**: The `.env` symlink doesn't exist

**Fix**:
```bash
# Create symlink to development
ln -sf .env.development .env

# Or use the helper
make switch-dev
```

### Error: "DB_URL is required"

**Cause**: Running `go run cmd/api/main.go` without `.env` existing

**Fix**:
```bash
# Always use make commands
make dev   # For development
make prod  # For production

# Or create the symlink first
make switch-dev
go run cmd/api/main.go
```

### Check Which Environment You're Using

```bash
# See what .env points to
ls -la .env

# Or use our helper
make env-status
```

### `.env` is a Regular File, Not a Symlink

If you manually created `.env`, it won't switch automatically.

**Fix**:
```bash
# Remove the file
rm .env

# Create symlink
make switch-dev
```

## Git and `.env` Files

### What's Committed to Git

 `.env.development` - Committed (safe defaults for local dev)
 `.env.production` - Committed (with placeholder secrets)
❌ `.env` - **NOT committed** (it's just a symlink)

### Before Committing

Make sure you haven't accidentally added real secrets to `.env.development` or `.env.production`:

```bash
# Run the automated guard test
go test ./internal/config -run TestTrackedEnvFilesContainNoLiveSecrets -v

# Check what will be committed
git diff .env.development
git diff .env.production

# Your production secrets should be in environment variables or CI/CD secrets
```

## Best Practices

### 1. Never Run `go run cmd/api/main.go` Directly

Always use:
```bash
make dev   # Development
make prod  # Production
make run   # Use current .env
```

### 2. Check Your Environment Before Running

```bash
make env-status
```

### 3. Development Secrets

For `.env.development`:
-  Use placeholder values
-  Use "admin" passwords for local services
-  Commit this file

### 4. Production Secrets

For `.env.production`:
-  Don't put real secrets here
-  Use placeholders
-  Set real secrets on your deployment platform (Render, etc.)

## Environment Variables Priority

When running the app:

1. **Environment variables** (highest priority)
2. **`.env` file** (which is a symlink)
3. **Default values in code** (lowest priority)

## Common Workflows

### Daily Development

```bash
# Morning
make dev

# Work on code...

# Evening
make docker-down
```

### Testing Production Config Locally

```bash
# Make sure you have internet and cloud services configured
make prod
```

### Deploying to Production

```bash
# On Render, set environment variables directly
# Don't rely on .env.production file

# Your deployment platform should set:
DB_URL=<supabase-url>
JWT_SECRET=<real-secret>
REDIS_URL=<upstash-url>
# etc.
```

## File Structure

```
.
├── .env                      # Symlink → .env.development or .env.production
├── .env.development          # Local dev config (committed)
├── .env.production           # Prod config template (committed)
├── docker-compose.yml        # References .env
└── Makefile                  # Handles env switching
```

## Quick Reference

| Command | What It Does |
|---------|-------------|
| `make env-status` | Show current environment |
| `make switch-dev` | Switch to development |
| `make switch-prod` | Switch to production |
| `make dev` | Auto-switch to dev and run |
| `make prod` | Auto-switch to prod and run |
| `make run` | Run with current .env |
| `ls -la .env` | See what .env points to |

## Advanced: Manual Symlink Management

If you want to manage the symlink yourself:

```bash
# Remove existing .env
rm .env

# Create symlink to development
ln -s .env.development .env

# Or to production
ln -s .env.production .env

# Check where it points
readlink .env
```

But it's easier to just use:
```bash
make switch-dev
make switch-prod
```
