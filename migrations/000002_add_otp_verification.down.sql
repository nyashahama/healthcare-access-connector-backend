 BEGIN;
 DROP FUNCTION IF EXISTS cleanup_expired_otps();
 DROP TABLE IF EXISTS otp_verifications CASCADE;
 COMMIT;
