# Issues Found During Code Review

Automated audit date: 2026-04-28

---

## CRITICAL

### 1. go.mod specifies nonexistent Go version (1.25.0)
**File:** `go.mod`
Go 1.25.0 does not exist — the latest is 1.24.x. This will break `go install`, toolchain resolution, and builds on some platforms. Change to `go 1.24.0`.

### 2. 6 out of 12 migration down files are empty
**Files:** `database/migrations/000006_*.down.sql`, `000008_*.down.sql`, `000009_*.down.sql`, `000010_*.down.sql`, `000011_*.down.sql`, `000012_*.down.sql`
These are zero-byte files. Rollbacks are impossible for these versions. Production databases would be unrecoverable if a rollback is needed. Each needs a proper `DROP TABLE` or reverse ALTER statement.

### 3. Missing indexes in up migrations 000009–000012
**Files:** `database/migrations/000009_consulatations.up.sql` through `000012_provider_availability.up.sql`
These migrations only contain `CREATE TABLE` statements but omit ALL indexes. The indexes exist in `database/schemas/telemedicine/*.sql` but were never copied into the migration files. This means production databases that only run migrations will have zero indexes on `consultations`, `consultation_messages`, `consultation_notes`, and `provider_availability` — causing full table scans.
**Fix:** Add the missing `CREATE INDEX` statements from the corresponding `database/schemas/` files into the up migrations.

---

## HIGH

### 4. Token validation caching is a security risk
**File:** `internal/service/core/auth_service.go:414-422`
Token validation results are cached for 1 minute using the raw token string as key. If a token is revoked/blacklisted during that window, it still validates. The logout path correctly invalidates the cache, but there's still a race condition.

### 5. Password reset succeeds even when email notification fails
**File:** `internal/service/core/auth_service.go:666-683`
The password is updated on line 666 THEN the email is sent on line 677. If email fails, a 503 is returned — but the password has already been changed irreversibly. The user now has a new password they don't know and no confirmation email.
**Fix:** Either send email first, or use a two-phase pattern (store new hash separately, only activate on successful email confirmation).

### 6. ResetPassword panics on phone-only users
**File:** `internal/service/core/auth_service.go:678`
Line 678 dereferences `*user.Email` without checking for nil. Users registered with only a phone number (no email) will cause a nil-pointer dereference and panic the server.

### 7. Logout returns 200 OK with invalid/expired token
**File:** `internal/handler/core/auth_handler.go:205-209`
When `ValidateToken` fails during logout, the handler returns HTTP 200 with "Logged out successfully" instead of an error. This misleads clients into thinking logout succeeded when it didn't.

### 8. In-memory rate limiting won't work with horizontal scaling
**File:** `internal/middleware/ratelimit.go:36-78`
Uses an in-process `map[string]*rateLimiter`. Multiple server instances have independent counters. Should use Redis for shared rate limiting.

### 9. Login rate limiting is in-memory only
**File:** `internal/service/core/auth_service.go:49-51`
Same multi-instance problem as #8. Uses `map[string]loginAttempt` with `sync.RWMutex`. The cleanup goroutine has no mechanism to stop on shutdown (resource leak on restart).

---

## MEDIUM

### 10. Migration filename typos: "consulatations"
**Files:**
- `database/migrations/000009_consulatations.up.sql` (should be `consultations`)
- `database/migrations/000010_consulatation_notes.up.sql` (should be `consultation_notes`)
- `database/migrations/000011_consulatation_messages.up.sql` (should be `consultation_messages`)
Typos in filenames make discovery and automation harder.

### 11. txManager parameter accepted but never stored/used
**File:** `internal/server/server.go:149`
`NewServer` accepts `repository.TxManager` but never stores it in the struct or uses it. Dead parameter.

### 12. bin/api binary committed to git
**File:** `bin/api` (22MB)
The compiled binary is tracked by git. Remove with `git rm --cached bin/api` and add `bin/` to `.gitignore` (already present).

### 13. Dead code: maskIP function
**File:** `internal/service/core/auth_service.go:1196-1205`
Function is defined but never called anywhere in the codebase.

### 14. CORS credentials + wildcard origin conflict
**File:** `internal/middleware/cors.go:38-40`
When `ALLOWED_ORIGINS=*`, it sets `Access-Control-Allow-Credentials: true`. Per the CORS spec, credentialed requests CANNOT use wildcard origins. Browsers may reject these responses.

### 15. CI doesn't run linting
**File:** `.github/workflows/ci.yml`
Only `go vet ./...` and `go test ./...` are run. No `golangci-lint`, no `gosec`, no static analysis. Add a lint step.

### 16. Port handling double-prepends ':'
**File:** `internal/config/config.go:177`
If the PORT environment variable is already `:8080` (with colon), this prepends another `:`, resulting in `::8080` and the server won't start.

### 17. Omitted jti claim in JWT
**File:** `internal/service/core/auth_service.go:1063-1071`
Generated JWTs lack a unique `jti` (JWT ID) claim, making per-token revocation tracking harder.

### 18. handlePostRegistration silently fails
**File:** `internal/service/core/auth_service.go:1018-1054`
If consent creation or patient profile creation fails, only a warning is logged. Users end up in an inconsistent state with no consent record or patient profile.

### 19. Password validation has no complexity requirement
**File:** `internal/validator/validator.go:15,80-84`
Only checks `len >= 8` characters. No requirement for uppercase, digits, or special characters. Weak for a healthcare application handling PHI.

### 20. GetBcryptCost mutates the config struct
**File:** `internal/config/config.go:366-372`
The method assigns `c.BcryptCost = 4` in development, permanently mutating the struct field. The original configured value is unrecoverable after calling this method.

### 21. getEnvAsDuration doesn't handle all time units
**File:** `internal/config/config.go:429-437`
The duration parser only special-cases keys containing `HOURS` or `MINUTES`. Keys like `CACHE_DEFAULT_TTL` (containing `TTL`) or other suffixes fall through to the `time.ParseDuration` path correctly, but the initial `strconv.Atoi` attempt may unintentionally parse duration strings as plain integers.

---

## LOW

### 22. os.Exit(0) in main.go is unreachable
**File:** `cmd/api/main.go:37`
`Run()` either blocks forever (graceful shutdown) or returns an error triggering `log.Fatal`. `os.Exit(0)` is dead code.

### 23. Login goroutine context lifetimes
**File:** `internal/service/core/auth_service.go:381,391`
Goroutines use `context.WithTimeout` with deferred cancels. Harmless but wasteful if the parent context is already cancelled.

### 24. Missing nbf (not before) claim in JWT
**File:** `internal/service/core/auth_service.go:1063-1071`
No `nbf` claim — tokens are valid immediately upon creation with no clock skew tolerance window.

### 25. Email config defaults to "ses" but env files use "resend"
**File:** `internal/email/config.go:15`
Default provider is `ses` while all `.env` files use `EMAIL_PROVIDER=resend`. Inconsistent default vs practice.

### 26. coverage.out tracked by git
**File:** `coverage.out`
Test coverage output is committed to the repository. Should be gitignored (already in `.gitignore` but may have been committed before the ignore rule was added).

### 27. database/migrations/000005_add_appointments_table.down.sql has only DROP TABLE
**File:** `database/migrations/000005_add_appointments_table.down.sql`
Contains only `DROP TABLE IF EXISTS appointments;` — enough to rollback but doesn't clean up related objects if created.

### 28. Missing error handling on email service close in recovery middleware
**File:** `internal/email` - `app.go:497-503`
The `emailService.Close()` error is only logged as a warning but no retry or escalation. Fine for now but worth monitoring.

---

## Summary
| Severity | Count |
|----------|-------|
| Critical | 3     |
| High     | 6     |
| Medium   | 12    |
| Low      | 7     |
| **Total** | **28** |

Priority order for addressing:
1. Fix go.mod Go version (CRITICAL)
2. Fill in empty migration down files (CRITICAL)
3. Add missing indexes to migrations 000009-000012 (CRITICAL)
4. Fix ResetPassword panic on phone-only users (HIGH)
5. Fix password reset order (update after email) (HIGH)
6. Fix token validation caching window (HIGH)
7. Rate limiting to Redis (HIGH)
8. Remaining items
