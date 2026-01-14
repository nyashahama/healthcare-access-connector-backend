# 🚀 Quick Start Guide

## First Time Setup (5 minutes)

```bash
# 1. Run the setup script
chmod +x scripts/setup-dev.sh
./scripts/setup-dev.sh

# 2. Generate a secure JWT secret
make generate-jwt

# 3. Update .env.development with the generated JWT_SECRET
# Open .env.development and replace JWT_SECRET value

# 4. Run database migrations
make migrate-up

# 5. Start the application
make dev
```

That's it! Your app is now running at **http://localhost:8080** 🎉

## Understanding `.env` Files

Your project has:
- **`.env`** → A symlink pointing to `.env.development` or `.env.production`
- **`.env.development`** → Local development config
- **`.env.production`** → Production config

The `make dev` and `make prod` commands automatically switch the `.env` symlink for you!

Check which environment you're using:
```bash
make env-status
```

## What Just Happened?

-  Local PostgreSQL database running (localhost:5432)
-  Local Redis cache running (localhost:6379)
-  Mailpit email catcher running (http://localhost:8025)
-  NATS message broker running (localhost:4222)
-  Your Go application connected to everything

## Daily Development

```bash
# Start coding (automatically starts services)
make dev

# When done for the day
make docker-down
```

## Testing Emails

1. Trigger any email in your app (e.g., register a user)
2. Open http://localhost:8025
3. See all emails caught by Mailpit
4. No real emails are sent!

## Common Commands

```bash
make dev           # Start development mode
make test          # Run tests
make fmt           # Format code
make docker-logs   # View service logs
make help          # See all commands
```

## Need More Help?

- See **DEVELOPMENT.md** for detailed guide
- See **README.md** for API documentation
- Run `make help` for all available commands

## Switching to Production

When you're ready to test with real cloud services:

```bash
make prod  # Uses Supabase, Upstash Redis, Resend Email
```

## Project Structure

```
.
├── cmd/api/               # Application entry point
├── internal/              # Application code
├── database/migrations/   # Database migrations
├── .env.development       # Local dev config
├── .env.production        # Production config
├── docker-compose.yml     # Docker services
└── Makefile              # All commands
```

## Troubleshooting

**Services won't start?**
```bash
make docker-clean
make docker-up
```

**Port already in use?**
```bash
lsof -ti:8080 | xargs kill -9
```

**Database issues?**
```bash
make docker-restart
make migrate-up
```


