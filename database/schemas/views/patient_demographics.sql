-- View for patient demographics
CREATE VIEW patient_demographics AS
SELECT 
    p.id,
    p.first_name,
    p.last_name,
    calculate_age(p.date_of_birth) as age,
    p.gender,
    p.province,
    p.city,
    p.language_preferences,
    p.requires_interpreter,
    m.blood_type,
    m.overall_health_status,
    COUNT(DISTINCT d.id) as number_of_dependents,
    u.created_at as registration_date
FROM patient_profiles p
LEFT JOIN patient_medical_info m ON p.id = m.patient_id
LEFT JOIN patient_dependents d ON p.id = d.patient_id
LEFT JOIN users u ON p.user_id = u.id
GROUP BY p.id, m.id, u.id;