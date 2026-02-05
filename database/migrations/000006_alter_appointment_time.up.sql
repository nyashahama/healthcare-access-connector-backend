-- Step 1: Add a new column with the correct type
ALTER TABLE appointments ADD COLUMN appointment_time_new TIME;

-- Step 2: Extract time from appointment_datetime (not from appointment_time which is DATE)
UPDATE appointments SET appointment_time_new = appointment_datetime::TIME;

-- Step 3: Drop the old column
ALTER TABLE appointments DROP COLUMN appointment_time;

-- Step 4: Rename the new column
ALTER TABLE appointments RENAME COLUMN appointment_time_new TO appointment_time;

-- Step 5: Add NOT NULL constraint
ALTER TABLE appointments ALTER COLUMN appointment_time SET NOT NULL;
