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

---

## Current findings while implementing (2026-05-25)

### A. `internal/service/sms/sms_service.go` was an empty package
**Status:** fixed locally in progress
The `service.SMSService` interface and repository implementation already existed, but the service package was just `package sms`. This left the SMS domain without a service-layer implementation for handlers/app wiring to depend on.

### B. SMS OTP delivery is still not production-ready
**Files:** `internal/service/core/otp_service.go`, `internal/service/sms/sms_service.go`, `internal/app/app.go`, `.env.example`
`GenerateOTP` still returns `503` for SMS delivery after persisting the OTP because there is no outbound SMS provider/configuration wired into the app yet. The repository-backed SMS service foundation exists, but outbound delivery, provider credentials, and OTP integration remain open.

### C. SMS provider rollout still needs operational verification
**Files:** `internal/config/config.go`, `.env.example`, `internal/service/core/twilio_sms.go`
Twilio-first delivery is the implementation direction, but production readiness still depends on real credentials, approved sender numbers/messaging service configuration, and live verification against Twilio in staging/production environments.

### D. SMS public handler surface was only dead scaffolding
**Status:** fixed locally in progress
**Files:** `internal/handler/sms/sms_handler.go`, `internal/handler/dto/core/user_dto.go`
The empty SMS handler file and the empty core user DTO file were unreferenced dead stubs. They have been removed so the codebase no longer implies a nonexistent SMS HTTP surface or duplicate DTO layer.

### E. NGO partner admin surface was missing
**Status:** fixed locally in progress
**Files:** `internal/handler/admin/ngo_handler.go`, `internal/handler/dto/admin/admin_dto.go`, `internal/server/server.go`, `internal/app/app.go`
The repo already had NGO partner domain/service/repository support, but no admin HTTP surface. A minimal admin API for creating and fetching NGO partner profiles by user ID has now been wired through the existing `AdminHandler`.

### F. OTP SMS audit trail leaked the verification code
**Status:** fixed locally in progress
**Files:** `internal/service/core/otp_service.go`, `internal/service/core/otp_service_audit_test.go`
Outbound OTP SMS persistence was storing the full message body, which included the live verification code. The audit trail now stores a redacted body while preserving provider metadata such as Twilio SID and status.

### G. Password reset notification order blocked valid resets
**Status:** fixed locally in progress
**Files:** `internal/service/core/auth_service.go`, `internal/service/core/auth_service_test.go`
`ResetPassword` was sending the "password changed" email before updating the password and returning `500` if the email failed. The flow now updates the password first and treats the notification as best-effort so a successful reset is not rolled back by email delivery problems.

### H. Session service cache access could panic when cache was nil
**Status:** fixed locally in progress
**Files:** `internal/service/core/session_service.go`, `internal/service/core/session_service_test.go`
The session service dereferenced `s.cache` in create/get/revoke/cache-invalidation paths without checking whether a cache service was configured. Cache access is now guarded consistently so nil or unavailable cache does not crash session operations.

### I. Session service could panic on short tokens in log fields
**Status:** fixed locally in progress
**Files:** `internal/service/core/session_service.go`, `internal/service/core/session_service_test.go`
Several session-service log statements sliced `token[:8]` directly. Malformed or short session tokens could therefore panic the service during normal error handling. Logging now uses a safe token-prefix helper.

### J. Admin services assumed cache was always configured
**Status:** fixed locally in progress
**Files:** `internal/service/admin/admin_service.go`, `internal/service/admin/ngo_service.go`, `internal/service/admin/admin_cache_test.go`
`GetSystemAdminByUserID` dereferenced `s.cache` without a nil/availability guard, and NGO partner lookup only checked for nil, not cache availability. Both admin lookups now treat cache as optional and have focused regression tests.

### K. User service assumed cache was always configured
**Status:** fixed locally in progress
**Files:** `internal/service/core/user_service.go`, `internal/service/core/user_service_test.go`
`GetUserByID`, `GetUserProfile`, and user-cache invalidation paths dereferenced `s.cache` directly. In deployments or tests without a cache service, profile reads and profile mutations could panic. User-service cache access is now guarded so cache is optional.

### L. More core services assumed cache was always configured
**Status:** fixed locally in progress
**Files:** `internal/service/core/consent_service.go`, `internal/service/core/notification_service.go`, `internal/service/core/audit_service.go`, `internal/service/core/cache_optional_service_test.go`
Consent, notification, and audit services also dereferenced `s.cache` directly in read-through caching and invalidation paths. Nil or unavailable cache could panic consent reads, notification preference reads/updates, and audit activity retrieval. These services now treat cache as optional and have focused nil-cache regression coverage.

### M. Allergy service assumed cache was always configured
**Status:** fixed locally in progress
**Files:** `internal/service/patients/allergy_service.go`, `internal/service/patients/allergy_service_test.go`
`allergyService` dereferenced `s.cache` directly in both read-through cache paths and in cache invalidation after add/update. Nil or unavailable cache could panic allergy reads and mutations. The service now treats cache as optional and has focused nil-cache regression coverage.

### N. Patient profile service assumed cache was always configured
**Status:** fixed locally in progress
**Files:** `internal/service/patients/patient_service.go`, `internal/service/patients/patient_service_test.go`
`patientService` dereferenced `s.cache` directly in profile-by-user, profile-by-id, demographics summary, search caching, and shared cache invalidation. Nil or unavailable cache could panic patient profile reads and profile mutations. The service now treats cache as optional and has focused nil-cache regression coverage.

### O. Credential deletion could not reliably audit or invalidate cache
**Status:** fixed locally in progress
**Files:** `internal/service/providers/credential_service.go`, `internal/repository/interfaces.go`, `internal/repository/providers/credential_repository.go`, `internal/repository/providers/credential_repository_test.go`, `internal/service/providers/credential_service_test.go`
`credentialService.DeleteCredential` tried to recover credential context by calling `GetStaffCredentials(ctx, uuid.Nil)` with an inline comment admitting it would not work. That meant deletion could silently miss cache invalidation and audit context. The repository contract now exposes direct credential lookup by ID, and delete uses that real lookup path.

### P. Patient search and demographics were stubbed or misleading
**Status:** fixed locally in progress
**Files:** `internal/service/patients/patient_service.go`, `internal/service/patients/patient_service_test.go`, `internal/repository/patients/patient_profile_repository.go`
`SearchPatients` returned an empty slice and `GetDemographicsSummary` returned a hard-coded zero summary. On top of that, `ListPatientProfiles` relied on a broken fake-null search parameter path. The patient service now performs real filtering and demographics aggregation, and the repository list path now delegates through name-search with an explicit empty query instead of the broken placeholder filter setup.

### Q. Staff creation could panic on nil user ID
**Status:** fixed locally in progress
**Files:** `internal/service/providers/staff_service.go`, `internal/service/providers/staff_service_test.go`
`CreateStaffMember` dereferenced `*staff.UserID` before checking whether the pointer itself was nil, even though `ClinicStaff.UserID` is nullable in the domain model. Malformed input could therefore panic the service instead of returning a validation error. The service now guards the pointer properly and has focused regression coverage.

### R. Emergency contact service assumed cache was always configured
**Status:** fixed locally in progress
**Files:** `internal/service/patients/emergency_contact_service.go`, `internal/service/patients/emergency_contact_service_test.go`
`emergencyContactService` dereferenced `s.cache` directly in both read-through cache paths and in shared cache invalidation after add/update. Nil or unavailable cache could panic emergency-contact reads and mutations. The service now treats cache as optional and has focused nil-cache regression coverage.

### S. Clinic service assumed cache was always configured
**Status:** fixed locally in progress
**Files:** `internal/service/providers/clinic_service.go`, `internal/service/providers/clinic_service_test.go`
`clinicService` dereferenced `c.cache` directly in clinic lookups, owner and verification lookups, search caching, registration-time user-cache invalidation, owner-transfer cache invalidation, and shared clinic cache invalidation. Nil or unavailable cache could panic core clinic registration, lookup, and ownership flows. The service now treats cache as optional and has focused nil-cache regression coverage.

### T. Medical info service assumed cache was always configured
**Status:** fixed locally in progress
**Files:** `internal/service/patients/medical_info_service.go`, `internal/service/patients/medical_info_service_test.go`
`medicalInfoService` dereferenced `s.cache` directly in both medical-info read-through cache paths and in shared cache invalidation after create, update, and delete. Nil or unavailable cache could panic medical-info reads and mutations. The service now treats cache as optional and has focused nil-cache regression coverage.

### U. Service catalog service assumed cache was always configured
**Status:** fixed locally in progress
**Files:** `internal/service/providers/service_catalog_service.go`, `internal/service/providers/service_catalog_service_test.go`
`serviceCatalogService` dereferenced `s.cache` directly in single-service lookups, clinic-service list lookups, active-service list lookups, and shared cache invalidation after create/update/delete. Nil or unavailable cache could panic service-catalog reads and mutations in the provider domain. The service now treats cache as optional and has focused nil-cache regression coverage.

### V. Immunization service assumed cache was always configured
**Status:** fixed locally in progress
**Files:** `internal/service/patients/immunization_service.go`, `internal/service/patients/immunization_service_test.go`
`immunizationService` dereferenced `s.cache` directly in immunization list reads, upcoming-immunization reads, and shared cache invalidation after add/update. Nil or unavailable cache could panic immunization reads and mutations in a core clinical-data path. The service now treats cache as optional and has focused nil-cache regression coverage.

### W. Family history service assumed cache was always configured
**Status:** fixed locally in progress
**Files:** `internal/service/patients/family_history_service.go`, `internal/service/patients/family_history_service_test.go`
`familyHistoryService` dereferenced `s.cache` directly in family-history reads and in shared cache invalidation after add/update, including the relative-specific invalidation path. Nil or unavailable cache could panic family-history reads and mutations in another core clinical-data path. The service now treats cache as optional and has focused nil-cache regression coverage.

### X. Condition service assumed cache was always configured
**Status:** fixed locally in progress
**Files:** `internal/service/patients/condition_service.go`, `internal/service/patients/condition_service_test.go`
`conditionService` dereferenced `s.cache` directly in condition reads, active-condition reads, and shared invalidation across both all-condition and status-specific cache keys. Nil or unavailable cache could panic condition reads and mutations in another core clinical-data path. The service now treats cache as optional and has focused nil-cache regression coverage.

### Y. Surgery service assumed cache was always configured
**Status:** fixed locally in progress
**Files:** `internal/service/patients/surgery_service.go`, `internal/service/patients/surgery_service_test.go`
`surgeryService` dereferenced `s.cache` directly in surgery-history reads, recent-surgery reads, and shared invalidation after add/update. Nil or unavailable cache could panic surgery reads and mutations in another core clinical-data path. The service now treats cache as optional and has focused nil-cache regression coverage.

### Z. Medication service assumed cache was always configured
**Status:** fixed locally in progress
**Files:** `internal/service/patients/medical_service.go`, `internal/service/patients/medical_service_test.go`
`medicationService` dereferenced `s.cache` directly in medication reads, active-medication reads, and shared invalidation across both all-medication and status-specific cache keys. Nil or unavailable cache could panic medication reads and mutations in another core clinical-data path. The service now treats cache as optional and has focused nil-cache regression coverage.

### AA. Dependent service assumed cache was always configured
**Status:** fixed locally in progress
**Files:** `internal/service/patients/dependent_service.go`, `internal/service/patients/dependent_service_test.go`
`dependentService` dereferenced `s.cache` directly in dependent list reads, child-dependent reads, and shared invalidation after add/update. Nil or unavailable cache could panic dependent reads and mutations in another core patient-data path. The service now treats cache as optional and has focused nil-cache regression coverage.

### AB. Dependent health record service assumed cache was always configured
**Status:** fixed locally in progress
**Files:** `internal/service/patients/dependent_health_records_service.go`, `internal/service/patients/dependent_health_records_service_test.go`
`dependentHealthRecordService` dereferenced `s.cache` directly in dependent health-record reads, growth-record reads, and shared invalidation after add/update. Nil or unavailable cache could panic dependent health-record reads and mutations in another core patient-data path. The service now treats cache as optional and has focused nil-cache regression coverage.

### AC. Staff service assumed cache was always configured
**Status:** fixed locally in progress
**Files:** `internal/service/providers/staff_service.go`, `internal/service/providers/staff_service_test.go`
`staffService` dereferenced `s.cache` directly in pending-invitation reads, staff lookups, clinic-staff list reads, active-clinic-staff reads, and shared invalidation after multiple staff mutations. Nil or unavailable cache could panic core provider staff-management flows. The service now treats cache as optional and has focused nil-cache regression coverage.

### AD. Credential service assumed cache was always configured
**Status:** fixed locally in progress
**Files:** `internal/service/providers/credential_service.go`, `internal/service/providers/credential_service_test.go`
`credentialService` dereferenced `c.cache` directly in staff-credential reads and shared invalidation after create/delete. Nil or unavailable cache could panic provider credential reads and mutations. The service now treats cache as optional and has focused nil-cache regression coverage.
AE. Auth cache-backed login lockout updates were non-atomic and could undercount failures
- Status: fixed locally
- Scope: `internal/service/core/auth_service.go`, `internal/cache/redis_cache.go`, `internal/service/core/auth_service_test.go`
- Problem:
  - The auth service already used cache for shared login-attempt state, but failed attempts were updated with a non-atomic `Get` plus `Set`.
  - Under concurrent failed logins, especially across instances sharing Redis, that could lose increments and weaken the lockout threshold.
  - The cached TTL also did not guarantee survival for lockout windows longer than the 15-minute fallback TTL.
- Fix:
  - Added an optional Redis `Eval` capability on the cache implementation.
  - `authService.recordFailedLogin` now uses an atomic Lua update when Redis is available, with fallback to the previous path otherwise.
  - The login-attempt TTL now survives at least as long as the configured lockout window.
AF. Redis rate-limiter runtime errors could fail closed and block healthy traffic
- Status: fixed locally
- Scope: `internal/middleware/ratelimit.go`, `internal/middleware/ratelimit_test.go`
- Problem:
  - The HTTP rate limiter prefers Redis for shared enforcement, but at request time any Redis `Eval` error returned `false`.
  - That means a transient Redis outage or timeout could start rejecting otherwise healthy requests with `429`, turning rate limiting into an outage amplifier.
- Fix:
  - Added a runtime in-memory fallback limiter for the Redis-backed rate limiter.
  - Redis runtime failures now degrade to local rate limiting instead of failing closed.
  - If no fallback exists, the limiter now fails open rather than blocking traffic.
AG. Telemedicine consultation transitions left provider active-queue cache stale
- Status: fixed locally
- Scope: `internal/service/telemedicine/consultation_service.go`, `internal/service/telemedicine/consultation_service_test.go`
- Problem:
  - Consultation transition paths invalidated the consultation detail cache, patient history cache, and waiting-room cache, but not the provider active-consultations cache.
  - After accept, cancel, complete, escalate, decline, or no-show transitions, providers could keep seeing stale active consultation lists until TTL expiry.
- Fix:
  - Extended consultation cache invalidation to include affected provider active-consultation cache keys.
  - Covered both cases where the provider already existed on the consultation and where the provider is newly assigned during acceptance.
  - Added focused regression tests for accept and complete transitions.
AH. Provider availability writes left filtered provider-discovery caches stale
- Status: fixed locally
- Scope: `internal/service/telemedicine/provider_availability_service.go`, `internal/service/telemedicine/consultation_service_test.go`
- Problem:
  - Provider availability mutations invalidated only the staff cache and the global `providers:available:all` cache.
  - Clinic-filtered and specialization-filtered provider discovery views could stay stale after providers went online, offline, changed accepting state, or updated status/wait time.
- Fix:
  - Added lightweight cache-key registries for available-provider list caches and specialization caches.
  - Availability writes now invalidate all registered filtered provider-discovery cache keys, not just the global list.
  - Added focused regression coverage for invalidation of registered filtered caches.
AI. Appointment reschedules could leave the old clinic-date cache stale
- Status: fixed locally
- Scope: `internal/service/appointments/appointments_service.go`, `internal/service/appointments/appointment_service_test.go`
- Problem:
  - `RescheduleAppointment` invalidated cache keys derived only from the updated appointment record.
  - When an appointment moved to a different day, the old `appointments:clinic:<id>:date:<old-date>` cache key was left behind until TTL expiry.
- Fix:
  - Reschedule now invalidates cache for both the pre-reschedule appointment view and the post-reschedule appointment view.
  - Added focused regression coverage proving both old and new clinic-date cache keys are cleared when the date changes.
AJ. Telemedicine message writes left unread badge caches stale
- Status: fixed locally
- Scope: `internal/service/telemedicine/consultation_messages_service.go`, `internal/service/telemedicine/consultation_service_test.go`
- Problem:
  - Message sends and soft deletes invalidated the thread cache but not unread-count caches.
  - Patients or providers could keep seeing stale unread badges until TTL expiry even after a new message arrived or an unread message was deleted.
- Fix:
  - `SendMessage` and `DeleteMessage` now invalidate unread-count cache keys for the affected sender role in addition to the thread cache.
  - Added focused regression coverage for send and delete paths.
AK. Single-message read receipts left telemedicine unread badge caches stale
- Status: fixed locally
- Scope: `internal/service/telemedicine/consultation_messages_service.go`, `internal/service/telemedicine/consultation_service_test.go`
- Problem:
  - Batch read-receipt paths invalidated unread-count caches, but `MarkMessageRead` did not.
  - Reading a single message could leave unread badges stale until TTL expiry even though the read state had already changed.
- Fix:
  - `MarkMessageRead` now loads the message first, preserves typed 404 handling, and invalidates the unread-count cache for the message sender role after a successful mark-read operation.
  - Added focused regression coverage for the single-message read path.
AL. Telemedicine thread-cache invalidation only cleared the default 20-message page
- Status: fixed locally
- Scope: `internal/service/telemedicine/consultation_messages_service.go`, `internal/service/telemedicine/consultation_service_test.go`
- Problem:
  - Message threads are cached by `consultation_id` and `limit`, but invalidation always deleted only `messages:thread:<id>:limit:20`.
  - Clients using another first-page size could keep seeing stale thread content after sends, deletes, or system events until TTL expiry.
- Fix:
  - Added a per-consultation registry of cached first-page thread keys.
  - Thread writes now invalidate all registered first-page thread cache keys for the consultation, not only the default 20-item key.
  - Added focused regression coverage for cross-limit invalidation.
AM. Consultation note writes left provider and patient history caches stale
- Status: fixed locally
- Scope: `internal/service/telemedicine/consultation_notes_service.go`, `internal/service/telemedicine/consultation_service_test.go`
- Problem:
  - Provider note history is cached by `staff_id` and `limit`, but invalidation only cleared the default `limit=20` key.
  - Patient note history cache was never invalidated on note creation, update, or finalisation.
  - Providers and patients could both keep seeing stale note-history views until TTL expiry after note edits or finalisation.
- Fix:
  - Added a per-provider registry of cached note-history keys so invalidation clears all registered first-page limits.
  - Added patient note-history invalidation on note create, update, finalise, and finalise-by-consultation flows.
  - Added focused regression coverage for patient history invalidation on create and multi-limit provider-history invalidation on finalise.
AN. Patient consultation history invalidation only cleared the default 20-item cache
- Status: fixed locally
- Scope: `internal/service/telemedicine/consultation_service.go`, `internal/service/telemedicine/consultation_service_test.go`
- Problem:
  - Patient consultation history is cached by `patient_id` and `limit`, but consultation mutations invalidated only `consultations:patient:<id>:limit:20`.
  - Clients requesting another first-page size could keep seeing stale consultation history after consultation creation or state changes until TTL expiry.
- Fix:
  - Added a per-patient registry of cached consultation-history keys.
  - Consultation mutations now invalidate all registered first-page consultation-history cache keys for the patient, not only the default 20-item key.
  - Added focused regression coverage for multi-limit invalidation.
AO. Symptom-checker patient session history invalidation only cleared the default 20-item cache
- Status: fixed locally
- Scope: `internal/service/telemedicine/symptom_checker_service.go`, `internal/service/telemedicine/consultation_service_test.go`
- Problem:
  - Patient symptom-session history is cached by `patient_id` and `limit`, but write paths invalidated only `symptom_sessions:patient:<id>:limit:20`.
  - Clients requesting another first-page size could keep seeing stale symptom-session history after submissions or conversion/status changes until TTL expiry.
- Fix:
  - Added a per-patient registry of cached symptom-session history keys.
  - Symptom-session write paths now invalidate all registered first-page history keys for the patient, not only the default 20-item key.
  - Added focused regression coverage for multi-limit invalidation on session conversion.
AP. Consultation payment and channel updates invalidated only the detail cache
- Status: fixed locally
- Scope: `internal/service/telemedicine/consultation_service.go`, `internal/service/telemedicine/consultation_service_test.go`
- Problem:
  - `UpdatePaymentStatus`, `UpdateConsultationChannel`, and follow-up linking only invalidated the single consultation detail cache key.
  - Patient consultation-history summaries include `payment_status` and `channel`, and provider/waiting-room views also include `channel`, so those views could remain stale after these mutations.
- Fix:
  - These consultation mutations now load the consultation first and invalidate the broader patient/provider/waiting-room cache set, not only the detail key.
  - Added focused regression coverage for payment-status and channel update invalidation behavior.
AQ. Appointment completion and generic status updates allowed impossible transitions
- Status: fixed locally
- Scope: `internal/service/appointments/appointments_service.go`, `internal/service/appointments/appointment_service_test.go`
- Problem:
  - `CompleteAppointment` did not verify the current appointment status before delegating to the repository.
  - `UpdateAppointmentStatus` accepted any enumerated status value without checking whether the transition was valid from the current state.
  - That could allow impossible workflow regressions like completing a cancelled appointment or moving a completed appointment back to pending.
- Fix:
  - `CompleteAppointment` now requires the appointment to already be `confirmed`.
  - Added explicit service-level appointment status transition rules:
    - `pending` -> `confirmed` or `cancelled`
    - `confirmed` -> `completed`, `cancelled`, or `no_show`
    - terminal states cannot transition further
  - Added focused regression coverage for valid and invalid transitions.
AR. Appointment cancellation allowed invalid terminal-state cancellations
- Status: fixed locally
- Scope: `internal/service/appointments/appointments_service.go`, `internal/service/appointments/appointment_service_test.go`
- Problem:
  - `CancelAppointment` enforced actor permissions but did not verify that the current appointment status was actually cancellable.
  - Completed, already-cancelled, or no-show appointments could still be sent down the cancellation path.
- Fix:
  - Appointment cancellation now requires the current status to be `pending` or `confirmed`.
  - Added focused regression coverage rejecting cancellation of a completed appointment.
AS. Appointment cancellation handler trusted caller-supplied actor IDs
- Status: fixed locally
- Scope: `internal/handler/appointments/appointments_handler.go`, `internal/handler/appointments/appointment_handler_test.go`
- Problem:
  - `CancelAppointment` accepted `cancelled_by` from the request body and passed it directly to the service.
  - Because the service’s ownership check relies on the acting user ID, a caller could spoof another patient’s UUID and potentially cancel that patient’s appointment.
- Fix:
  - The handler now requires an authenticated user and always uses `claims.UserID` from context as the acting canceller.
  - Added regression coverage proving the handler ignores spoofed body IDs and rejects unauthenticated cancellation attempts.
AT. Appointment mutation methods lacked actor-aware authorization
- Status: fixed locally
- Scope: `internal/service/interfaces.go`, `internal/service/appointments/appointments_service.go`, `internal/service/appointments/appointment_service_test.go`, `internal/handler/appointments/appointments_handler.go`, `internal/handler/appointments/appointment_handler_test.go`
- Problem:
  - `UpdateAppointmentNotes`, `CompleteAppointment`, `UpdateAppointmentStatus`, and `DeleteAppointment` did not carry the acting user into the service layer.
  - That meant the service boundary itself could not enforce who was allowed to perform those appointment-management actions.
  - The corresponding handlers also did not require authenticated users before invoking those mutations.
- Fix:
  - The appointment service contract now requires an acting user for those privileged mutations.
  - The service now rejects patient actors for appointment-management actions before mutating state.
  - The handlers now require authenticated users and always pass `claims.UserID` as the acting user.
  - Added focused service and handler regression coverage for authorization and actor propagation.
AU. Patient-scoped appointment history and count handlers trusted path IDs
- Status: fixed locally
- Scope: `internal/handler/appointments/appointments_handler.go`, `internal/handler/appointments/appointment_handler_test.go`
- Problem:
  - `GetAppointmentsByPatient` and `GetAppointmentCount` accepted `patientId` from the route and forwarded it directly to the service.
  - An authenticated patient could request another patient's appointment history or count by changing the path UUID.
- Fix:
  - Both handlers now require an authenticated user.
  - Patient callers may only access their own `patientId`; other patient IDs are rejected with `403`.
  - Added regression coverage for authenticated success, unauthenticated rejection, and patient-to-patient access denial.
AV. Appointment creation trusted caller-supplied patient IDs
- Status: fixed locally
- Scope: `internal/handler/appointments/appointments_handler.go`, `internal/handler/appointments/appointment_handler_test.go`
- Problem:
  - `CreateAppointment` accepted `patient_id` from the request body without comparing it to the authenticated caller.
  - An authenticated patient could attempt to create appointments for another user by changing the body UUID.
- Fix:
  - The handler now requires an authenticated user.
  - Patient callers may only create appointments for their own user ID; mismatches are rejected with `403`.
  - Added regression coverage for authenticated success, unauthenticated rejection, and patient spoofing denial.
AW. Appointment detail and clinic schedule reads lacked authorization gates
- Status: fixed locally
- Scope: `internal/handler/appointments/appointments_handler.go`, `internal/handler/appointments/appointment_handler_test.go`
- Problem:
  - `GetAppointmentByID` returned appointment details by raw appointment UUID without checking whether the caller owned or was entitled to view that appointment.
  - Clinic-scoped appointment list routes returned clinic schedules without any authenticated role gate.
- Fix:
  - `GetAppointmentByID` now requires authentication and only allows the owning patient or privileged clinic roles to view the appointment.
  - Clinic schedule routes now require authentication and restrict access to provider-side roles.
  - Added focused regression coverage for owner access, unauthenticated rejection, patient access denial, and privileged clinic-list access.
AX. Appointment rescheduling lacked actor-aware authorization
- Status: fixed locally
- Scope: `internal/service/interfaces.go`, `internal/service/appointments/appointments_service.go`, `internal/service/appointments/appointment_service_test.go`, `internal/handler/appointments/appointments_handler.go`, `internal/handler/appointments/appointment_handler_test.go`
- Problem:
  - `RescheduleAppointment` did not carry the acting user into the service layer.
  - The handler also did not require an authenticated user before rescheduling.
  - That meant a patient could reach the reschedule path without any ownership check at the service boundary.
- Fix:
  - The appointment service contract now requires the acting user for reschedules.
  - The service now allows only the owning patient or privileged provider-side roles to reschedule.
  - The handler now requires authentication and passes `claims.UserID` through to the service.
  - Added focused service and handler regression coverage for owner access, spoof denial, and unauthenticated rejection.
AY. Clinic-side appointment reads were role-gated but not clinic-affiliation-gated
- Status: fixed locally
- Scope: `internal/service/interfaces.go`, `internal/service/appointments/appointments_service.go`, `internal/service/appointments/appointment_service_test.go`, `internal/handler/appointments/appointments_handler.go`, `internal/handler/appointments/appointment_handler_test.go`
- Problem:
  - Clinic schedule routes and provider-side appointment detail access were previously allowed based only on broad role checks.
  - A provider-side user from clinic A could still target clinic B schedule routes if they had the right role.
- Fix:
  - Appointment read methods now carry the acting user into the service layer.
  - The service now enforces clinic-side access using `PrimaryClinicID` for `provider_staff`, `doctor`, and `clinic_admin`.
  - `system_admin` still retains global access.
  - Added focused service and handler regression coverage for same-clinic access and cross-clinic denial.
AZ. Appointment detail authorization could be bypassed on cache hits
- Status: fixed locally
- Scope: `internal/service/appointments/appointments_service.go`, `internal/service/appointments/appointment_service_test.go`
- Problem:
  - `GetAppointmentByID` performed authorization only after a repository fetch.
  - If the appointment detail was served from cache, the method returned early and skipped the new clinic-affiliation and ownership checks.
- Fix:
  - Cached appointment reads now run through the same `authorizeAppointmentRead` path before returning.
  - Added focused regression coverage for cross-clinic denial on a cache hit.
BA. Provider-side appointment mutations were not clinic-affiliation-gated
- Status: fixed locally
- Scope: `internal/service/appointments/appointments_service.go`, `internal/service/appointments/appointment_service_test.go`
- Problem:
  - Several appointment mutation paths validated actor role but not whether that actor belonged to the appointment's clinic.
  - A provider-side user who knew another clinic's appointment UUID could still attempt to confirm, reschedule, update notes, update status, complete, delete, or cancel across clinics.
- Fix:
  - Provider-side mutation authorization now checks `PrimaryClinicID` against the target appointment `ClinicID`.
  - Reschedule, confirm, notes update, complete, status update, delete, and clinic-side cancellation now enforce same-clinic access.
  - Added focused regression coverage for cross-clinic denial on confirmation and notes updates.
BB. Symptom-checker provider and admin routes lacked role gates
- Status: fixed locally
- Scope: `internal/handler/telemedicine/symptom_checker_handler.go`, `internal/handler/telemedicine/symptom_checker_handler_test.go`
- Problem:
  - Provider-facing `GetSessionWithPatientContext` and admin analytics routes were exposed without explicit role checks in the handler.
  - An authenticated patient or other non-admin user could reach sensitive provider/admin symptom-checker surfaces.
- Fix:
  - Added a shared `requireRole` helper in the symptom-checker handler.
  - `GetSessionWithPatientContext` now requires one of: `provider_staff`, `doctor`, `clinic_admin`, `system_admin`.
  - Admin analytics routes now require `system_admin`.
  - Added focused handler regression coverage for allowed provider/admin access, forbidden non-admin/provider access, and unauthenticated rejection.
BC. Consultation waiting-room route lacked staff authentication
- Status: fixed locally
- Scope: `internal/handler/telemedicine/consultation_handler.go`, `internal/handler/telemedicine/consultation_handler_test.go`
- Problem:
  - `GetWaitingRoom` exposed the provider queue without resolving or requiring authenticated staff identity.
  - A caller could hit the waiting-room route without passing through the provider identity boundary used elsewhere in the consultation handler.
- Fix:
  - `GetWaitingRoom` now requires `resolveStaffID(...)` before returning queue data.
  - Updated the handler tests to include authenticated staff context and added an unauthenticated rejection case.
BD. Consultation billing/admin mutation routes lacked staff authentication
- Status: fixed locally
- Scope: `internal/handler/telemedicine/consultation_handler.go`, `internal/handler/telemedicine/consultation_handler_test.go`
- Problem:
  - `UpdatePaymentStatus` and `LinkFollowUpAppointment` accepted requests without resolving authenticated staff identity.
  - That left sensitive consultation billing/admin mutations exposed outside the provider staff boundary used elsewhere in the handler.
- Fix:
  - Both routes now require `resolveStaffID(...)` before mutating consultation state.
  - Added focused handler regression coverage for authenticated staff access and unauthenticated rejection on both routes.
BE. Consultation provider lifecycle transitions lacked staff authentication
- Status: fixed locally
- Scope: `internal/handler/telemedicine/consultation_handler.go`, `internal/handler/telemedicine/consultation_handler_test.go`
- Problem:
  - `StartConsultation`, `DeclineConsultation`, and `MarkNoShow` mutated provider-side consultation lifecycle state without resolving authenticated staff identity first.
  - Those routes were weaker than the surrounding provider consultation handlers that already enforce staff identity.
- Fix:
  - All three routes now require `resolveStaffID(...)` before invoking the consultation service.
  - Updated `StartConsultation` tests to include staff resolution and added unauthenticated rejection coverage.
  - Added focused handler tests for authenticated staff access and unauthenticated rejection on decline and no-show transitions.
BF. Consultation channel updates lacked actor-bound authorization
- Status: fixed locally
- Scope: `internal/handler/telemedicine/consultation_handler.go`, `internal/handler/telemedicine/consultation_handler_test.go`
- Problem:
  - `UpdateConsultationChannel` was exposed as a shared route but did not bind the mutation to the authenticated consultation participant.
  - Any authenticated caller with a consultation UUID could attempt to change the consultation channel.
- Fix:
  - The handler now requires authentication, loads the consultation, and only allows the owning patient or the assigned provider staff to change the channel.
  - Added focused handler regression coverage for owning patient access, assigned provider access, unrelated-user denial, and unauthenticated rejection.
BG. Consultation detail reads were lacking actor binding
- Status: fixed locally
- Scope: `internal/handler/telemedicine/consultation_handler.go`, `internal/handler/telemedicine/consultation_handler_test.go`
- Problem:
  - `GetConsultationByID` and `GetConsultationWithDetails` loaded consultation data by UUID without requiring caller ownership or assignment.
  - A user with a valid consultation UUID could read detail data for a consultation they did not own or manage.
- Fix:
  - Both read handlers now require authenticated caller context and allow access only to the owning patient or assigned provider staff.
  - Added focused handler regression coverage for owning patient access, assigned provider access, unrelated-user denial, and unauthenticated rejection.
