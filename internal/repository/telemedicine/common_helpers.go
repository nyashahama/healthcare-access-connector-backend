package telemedicine

import (
	"encoding/json"
	"fmt"
	"math/big"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain/telemedicine"
	"github.com/rs/zerolog/log"
)

// UUID conversion helpers
func uuidToPgtypeUUID(id uuid.UUID) pgtype.UUID {
	return pgtype.UUID{
		Bytes: id,
		Valid: true,
	}
}

func uuidPtrToPgtypeUUID(id *uuid.UUID) pgtype.UUID {
	if id == nil {
		return pgtype.UUID{Valid: false}
	}
	return pgtype.UUID{
		Bytes: *id,
		Valid: true,
	}
}

func pgtypeUUIDToUUID(id pgtype.UUID) uuid.UUID {
	if !id.Valid {
		return uuid.Nil
	}
	return id.Bytes
}

func uuidPtrToUUID(u pgtype.UUID) *uuid.UUID {
	if !u.Valid {
		return nil
	}
	result := uuid.UUID(u.Bytes)
	return &result
}

// Text conversion helpers
func pgtypeTextFromString(s string) pgtype.Text {
	return pgtype.Text{
		String: s,
		Valid:  true,
	}
}

func pgtypeTextFromStringPtr(s *string) pgtype.Text {
	if s == nil {
		return pgtype.Text{Valid: false}
	}
	return pgtype.Text{
		String: *s,
		Valid:  true,
	}
}

func pgtypeTextToString(t pgtype.Text) string {
	if !t.Valid {
		return ""
	}
	return t.String
}

func pgtypeTextToStringPtr(t pgtype.Text) *string {
	if !t.Valid {
		return nil
	}
	return &t.String
}

func stringToStringPtr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// Interface to string conversion helper
func interfaceToString(i interface{}) string {
	if i == nil {
		return ""
	}

	switch v := i.(type) {
	case string:
		return v
	case *string:
		if v == nil {
			return ""
		}
		return *v
	case pgtype.Text:
		return pgtypeTextToString(v)
	default:
		// Fallback: convert to string using fmt
		return fmt.Sprintf("%v", i)
	}
}

// Interface to string pointer conversion helper
func interfaceToStringPtr(i interface{}) *string {
	if i == nil {
		return nil
	}

	switch v := i.(type) {
	case string:
		if v == "" {
			return nil
		}
		return &v
	case *string:
		return v
	case pgtype.Text:
		return pgtypeTextToStringPtr(v)
	default:
		str := fmt.Sprintf("%v", i)
		return &str
	}
}

// Boolean conversion helpers
func pgtypeBoolToBool(b pgtype.Bool) bool {
	if !b.Valid {
		return false
	}
	return b.Bool
}

// Timestamp conversion helpers
func pgtypeTimestampToTimePtr(t pgtype.Timestamp) *time.Time {
	if !t.Valid {
		return nil
	}
	return &t.Time
}

func timePtrToPgtypeTimestamp(t *time.Time) pgtype.Timestamp {
	if t == nil {
		return pgtype.Timestamp{Valid: false}
	}
	return pgtype.Timestamp{
		Time:  *t,
		Valid: true,
	}
}

// Date conversion helpers
func pgtypeDateToTimePtr(d pgtype.Date) *time.Time {
	if !d.Valid {
		return nil
	}
	return &d.Time
}

func datePtrToPgtypeDate(t *time.Time) pgtype.Date {
	if t == nil {
		return pgtype.Date{Valid: false}
	}
	return pgtype.Date{
		Time:  *t,
		Valid: true,
	}
}

// Int4 conversion helpers
func pgtypeInt4ToIntPtr(i pgtype.Int4) *int {
	if !i.Valid {
		return nil
	}
	val := int(i.Int32)
	return &val
}

func pgtypeInt4ToInt(i pgtype.Int4) int {
	if !i.Valid {
		return 0
	}
	val := int(i.Int32)
	return val
}

func intPtrToPgtypeInt4(i *int) pgtype.Int4 {
	if i == nil {
		return pgtype.Int4{Valid: false}
	}
	return pgtype.Int4{
		Int32: int32(*i),
		Valid: true,
	}
}

// Numeric (for float64/decimal) conversion helpers
func pgtypeNumericToFloat64Ptr(n pgtype.Numeric) *float64 {
	if !n.Valid {
		return nil
	}

	// Convert pgtype.Numeric to float64
	if n.Int == nil {
		return nil
	}

	// Create a big.Float from the Int and apply the exponent
	bigFloat := new(big.Float).SetInt(n.Int)

	// Apply the exponent (10^exp)
	if n.Exp != 0 {
		multiplier := new(big.Float).SetFloat64(1.0)
		for i := int32(0); i < n.Exp; i++ {
			multiplier.Mul(multiplier, big.NewFloat(10.0))
		}
		for i := int32(0); i > n.Exp; i-- {
			multiplier.Quo(multiplier, big.NewFloat(10.0))
		}
		bigFloat.Mul(bigFloat, multiplier)
	}

	val, _ := bigFloat.Float64()
	return &val
}

func float64PtrToPgtypeNumeric(f *float64) pgtype.Numeric {
	if f == nil {
		return pgtype.Numeric{Valid: false}
	}

	// Convert float64 to pgtype.Numeric
	bigFloat := big.NewFloat(*f)

	// Convert to integer representation with exponent
	// For simplicity, we'll use a fixed precision
	const precision = 8
	multiplier := big.NewFloat(1.0)
	for i := 0; i < precision; i++ {
		multiplier.Mul(multiplier, big.NewFloat(10.0))
	}

	bigFloat.Mul(bigFloat, multiplier)
	bigInt, _ := bigFloat.Int(nil)

	return pgtype.Numeric{
		Int:   bigInt,
		Exp:   -precision,
		Valid: true,
	}
}

// JSONB conversion helpers for map[string]any
func jsonbFromMap(m map[string]any) ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return json.Marshal(m)
}

func mapFromJSONB(data []byte) map[string]any {
	if len(data) == 0 {
		return nil
	}

	var result map[string]any
	if err := json.Unmarshal(data, &result); err != nil {
		return nil
	}
	return result
}

// JSONB conversion helpers for string slices
func jsonbFromStringSlice(s []string) ([]byte, error) {
	if s == nil {
		return nil, nil
	}
	return json.Marshal(s)
}

func stringSliceFromJSONB(data []byte) []string {
	if len(data) == 0 {
		return nil
	}

	var result []string
	if err := json.Unmarshal(data, &result); err != nil {
		return nil
	}
	return result
}

// Array conversion helpers (for PostgreSQL arrays like VARCHAR[])
func stringSliceToArray(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func stringPtrToString(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// Float64 pointer conversion helpers
func float64ToFloat64Ptr(f float64) *float64 {
	return &f
}

func float64PtrToFloat64(f *float64) float64 {
	if f == nil {
		return 0
	}
	return *f
}

// Helper conversion functions
func int32PtrToPgtypeInt4(val *int) pgtype.Int4 {
	if val == nil {
		return pgtype.Int4{Valid: false}
	}
	return pgtype.Int4{Int32: int32(*val), Valid: true}
}

func pgtypeBoolToBoolPtr(val pgtype.Bool) *bool {
	if !val.Valid {
		return nil
	}
	result := val.Bool
	return &result
}

// FIXED: Proper JSONB conversion for PostgreSQL using pgtype
func interfaceToPgtypeJSON(data interface{}) []byte {
	// Handle nil case - return nil (pgx will handle as NULL)
	if data == nil {
		return nil
	}

	// If it's already a byte slice, validate it's proper JSON
	if bytes, ok := data.([]byte); ok {
		if json.Valid(bytes) {
			return bytes
		}
		// If invalid, fall through to marshaling
	}

	// Marshal the data to JSON
	jsonBytes, err := json.Marshal(data)
	if err != nil {
		// Log the error and return nil
		log.Error().
			Err(err).
			Interface("data", data).
			Type("data_type", data).
			Msg("Failed to marshal data to JSON for permissions field")
		return nil
	}

	// Ensure we have valid JSON
	if len(jsonBytes) == 0 || !json.Valid(jsonBytes) {
		log.Warn().
			Str("json_bytes", string(jsonBytes)).
			Msg("Generated invalid JSON, returning nil")
		return nil
	}

	// Log successful conversion for debugging
	log.Debug().
		Str("json_output", string(jsonBytes)).
		Interface("input_data", data).
		Msg("Successfully converted to JSON")

	return jsonBytes
}

// Convert interface{} to json.RawMessage for JSONB columns
func interfaceToJSONRawMessage(data interface{}) json.RawMessage {
	if data == nil {
		return nil
	}

	jsonBytes, err := json.Marshal(data)
	if err != nil {
		log.Error().
			Err(err).
			Interface("data", data).
			Msg("Failed to marshal data to JSON RawMessage")
		return nil
	}

	// Validate JSON
	if !json.Valid(jsonBytes) {
		log.Error().
			Str("json_bytes", string(jsonBytes)).
			Msg("Generated invalid JSON for RawMessage")
		return nil
	}

	log.Debug().
		Str("json_output", string(jsonBytes)).
		Interface("input_data", data).
		Msg("Successfully converted to JSON RawMessage")

	return json.RawMessage(jsonBytes)
}

// NEW: Use this instead for JSONB columns - returns pgtype.JSONB
// NOTE: This may not work with all pgx versions - use interfaceToJSONRawMessage instead
// func interfaceToPgtypeJSONB(data interface{}) pgtype.JSONB {
// 	if data == nil {
// 		return pgtype.JSONB{Valid: false}
// 	}
//
// 	jsonBytes, err := json.Marshal(data)
// 	if err != nil {
// 		log.Error().
// 			Err(err).
// 			Interface("data", data).
// 			Msg("Failed to marshal data to JSONB")
// 		return pgtype.JSONB{Valid: false}
// 	}
//
// 	// Validate JSON
// 	if !json.Valid(jsonBytes) {
// 		log.Error().
// 			Str("json_bytes", string(jsonBytes)).
// 			Msg("Generated invalid JSON for JSONB")
// 		return pgtype.JSONB{Valid: false}
// 	}
//
// 	log.Debug().
// 		Str("json_output", string(jsonBytes)).
// 		Interface("input_data", data).
// 		Msg("Successfully converted to JSONB")
//
// 	return pgtype.JSONB{
// 		Bytes: jsonBytes,
// 		Valid: true,
// 	}
// }

func pgtypeJSONToInterface(data []byte) interface{} {
	if len(data) == 0 {
		return nil
	}

	var result interface{}
	if err := json.Unmarshal(data, &result); err != nil {
		log.Error().
			Err(err).
			Str("data", string(data)).
			Msg("Failed to unmarshal JSON")
		return nil
	}
	return result
}

// Helper to convert json.RawMessage to interface{}
func jsonRawMessageToInterface(data json.RawMessage) interface{} {
	if len(data) == 0 {
		return nil
	}

	var result interface{}
	if err := json.Unmarshal(data, &result); err != nil {
		log.Error().
			Err(err).
			Str("data", string(data)).
			Msg("Failed to unmarshal JSON RawMessage")
		return nil
	}
	return result
}

// Helper to convert pgtype.JSONB to interface{}
// NOTE: This may not work with all pgx versions
// func pgtypeJSONBToInterface(data pgtype.JSONB) interface{} {
// 	if !data.Valid || len(data.Bytes) == 0 {
// 		return nil
// 	}
//
// 	var result interface{}
// 	if err := json.Unmarshal(data.Bytes, &result); err != nil {
// 		log.Error().
// 			Err(err).
// 			Str("data", string(data.Bytes)).
// 			Msg("Failed to unmarshal JSONB")
// 		return nil
// 	}
// 	return result
// }

// attachmentTypePtr converts a *string to a typed *AttachmentType.
func attachmentTypePtr(s *string) *telemedicine.AttachmentType {
	if s == nil {
		return nil
	}
	v := telemedicine.AttachmentType(*s)
	return &v
}

// attachmentTypeToStringPtr converts a typed *AttachmentType to *string for pgtype helpers.
func attachmentTypeToStringPtr(at *telemedicine.AttachmentType) *string {
	if at == nil {
		return nil
	}
	s := string(*at)
	return &s
}

// referralTypePtr converts a *string to a typed *ReferralType.
func referralTypePtr(s *string) *telemedicine.ReferralType {
	if s == nil {
		return nil
	}
	v := telemedicine.ReferralType(*s)
	return &v
}

// referralTypeToStringPtr converts a typed *ReferralType to *string for pgtype helpers.
func referralTypeToStringPtr(rt *telemedicine.ReferralType) *string {
	if rt == nil {
		return nil
	}
	s := string(*rt)
	return &s
}

// prescriptionItemsFromJSONB unmarshals the JSONB prescription_details array into
// a typed []PrescriptionItem slice. Returns nil on empty or malformed input.
func prescriptionItemsFromJSONB(data json.RawMessage) []telemedicine.PrescriptionItem {
	if len(data) == 0 {
		return nil
	}
	var items []telemedicine.PrescriptionItem
	if err := json.Unmarshal(data, &items); err != nil {
		return nil
	}
	return items
}
