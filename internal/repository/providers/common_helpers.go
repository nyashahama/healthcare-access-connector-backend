package providers

import (
	"encoding/json"
	"fmt"
	"math/big"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
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
