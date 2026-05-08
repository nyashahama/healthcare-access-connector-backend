package sms

import (
	"encoding/json"
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

func pgtypeUUIDToUUIDPtr(id pgtype.UUID) *uuid.UUID {
	if !id.Valid {
		return nil
	}
	result := uuid.UUID(id.Bytes)
	return &result
}

// Text conversion helpers
func pgtypeTextFromStringPtr(v *string) pgtype.Text {
	if v == nil {
		return pgtype.Text{Valid: false}
	}
	return pgtype.Text{
		String: *v,
		Valid:  true,
	}
}

func pgtypeTextToStringPtr(v pgtype.Text) *string {
	if !v.Valid {
		return nil
	}
	return &v.String
}

func pgtypeTextToString(v pgtype.Text) string {
	if !v.Valid {
		return ""
	}
	return v.String
}

func pgtypeTextFromString(v string) pgtype.Text {
	return pgtype.Text{
		String: v,
		Valid:  true,
	}
}

// Timestamp conversion helpers
func pgtypeTimestampToTimePtr(v pgtype.Timestamp) *time.Time {
	if !v.Valid {
		return nil
	}
	return &v.Time
}

// JSONB conversion helpers
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

// Numeric conversion helpers
func float64PtrToPgtypeNumeric(v *float64) pgtype.Numeric {
	if v == nil {
		return pgtype.Numeric{Valid: false}
	}

	// Use fixed precision to preserve reasonable decimal values.
	bigFloat := big.NewFloat(*v)
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


func pgtypeNumericToFloat64Ptr(v pgtype.Numeric) *float64 {
	if !v.Valid || v.Int == nil {
		return nil
	}

	bf := new(big.Float).SetInt(v.Int)
	if v.Exp != 0 {
		multiplier := new(big.Float).SetFloat64(1.0)
		for i := int32(0); i < v.Exp; i++ {
			multiplier.Mul(multiplier, big.NewFloat(10.0))
		}
		for i := int32(0); i > v.Exp; i-- {
			multiplier.Quo(multiplier, big.NewFloat(10.0))
		}
		bf.Mul(bf, multiplier)
	}

	f, _ := bf.Float64()
	return &f
}

// Numeric/int conversions for messages
func intToPgtypeInt4(v int) pgtype.Int4 {
	return pgtype.Int4{
		Int32: int32(v),
		Valid: true,
	}
}
