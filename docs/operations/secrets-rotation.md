# Secret Rotation Guide

This document describes how to rotate credentials after the repository was previously tracked with live secrets.

## Rotation Checklist

1. Rotate Supabase or Postgres credentials.
2. Rotate Upstash Redis credentials.
3. Rotate Resend API credentials.
4. Rotate SMTP credentials if still used.
5. Rotate JWT signing secret.
6. Rotate AI-related tokens (DeepSeek, OpenAI, HuggingFace).
7. Revoke old tokens at each provider.
8. Remove secrets from git history using the team-approved process (e.g., `git-filter-repo` or BFG Repo-Cleaner).

## Post-Rotation Verification

- Run `go test ./internal/config -run TestTrackedEnvFilesContainNoLiveSecrets -v` to confirm no live secrets remain in tracked env files.
- Confirm `.env.development` and `.env.production` contain only placeholders.
- Confirm `.gitignore` blocks `.env` and `.env.*.local` files.

## Local Development Setup

After cloning the repository:

1. Copy `.env.development` to `.env.local` (optional, for local overrides).
2. Replace placeholder values in `.env.local` or set them as environment variables.
3. For Docker-based local dev, the default `.env.development` values should work without modification.

## Production Deployment

Production secrets must be sourced from:
- Environment variables set on the deployment platform (Render, Fly.io, etc.), **or**
- A secret manager (AWS Secrets Manager, 1Password Secrets Automation, etc.).

Never commit production secrets to the repository.
