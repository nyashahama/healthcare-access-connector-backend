// Package pgutils provides utility functions for PostgreSQL type conversions
// Reduces boilerplate when working with pgx/v5 pgtype package
package pgutils

import (
	"time"

	"github.com/docker/distribution/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

// ========================================
// Generic Pointer Helpers
// ========================================

// ToPtr converts a value to a pointer if valid is true, otherwise returns nil
func ToPtr[T any](v T, valid bool) *T {
	if !valid {
		return nil
	}
	return &v
}

// FromPtr returns the value from a pointer, or zero value if nil
func FromPtr[T any](ptr *T) T {
	if ptr == nil {
		var zero T
		return zero
	}
	return *ptr
}

// ========================================
// String Conversions
// ========================================

// StringToPtr converts a string to *string, returns nil if empty
func StringToPtr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// StringFromPtr returns string from pointer, empty string if nil
func StringFromPtr(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// ========================================
// pgtype.Text Conversions
// ========================================

// TextToString converts pgtype.Text to string
func TextToString(t pgtype.Text) string {
	if !t.Valid {
		return ""
	}
	return t.String
}

// TextToPtr converts pgtype.Text to *string
func TextToPtr(t pgtype.Text) *string {
	if !t.Valid {
		return nil
	}
	return &t.String
}

// TextFrom converts string to pgtype.Text
func TextFrom(s string) pgtype.Text {
	if s == "" {
		return pgtype.Text{Valid: false}
	}
	return pgtype.Text{String: s, Valid: true}
}

// TextFromPtr converts *string to pgtype.Text
func TextFromPtr(s *string) pgtype.Text {
	if s == nil {
		return pgtype.Text{Valid: false}
	}
	return pgtype.Text{String: *s, Valid: true}
}

// ========================================
// pgtype.Bool Conversions
// ========================================

// BoolFrom converts bool to pgtype.Bool
func BoolFrom(b bool) pgtype.Bool {
	return pgtype.Bool{Bool: b, Valid: true}
}

// BoolFromPtr converts *bool to pgtype.Bool
func BoolFromPtr(b *bool) pgtype.Bool {
	if b == nil {
		return pgtype.Bool{Valid: false}
	}
	return pgtype.Bool{Bool: *b, Valid: true}
}

// BoolTo converts pgtype.Bool to bool (false if invalid)
func BoolTo(b pgtype.Bool) bool {
	if !b.Valid {
		return false
	}
	return b.Bool
}

// BoolToPtr converts pgtype.Bool to *bool
func BoolToPtr(b pgtype.Bool) *bool {
	if !b.Valid {
		return nil
	}
	return &b.Bool
}

// ========================================
// UUID Conversions
// ========================================

// UUIDTo converts pgtype.UUID to uuid.UUID
func UUIDTo(u pgtype.UUID) uuid.UUID {
	return uuid.UUID(u.Bytes)
}

// UUIDToPtr converts pgtype.UUID to *uuid.UUID
func UUIDToPtr(u pgtype.UUID) *uuid.UUID {
	if !u.Valid {
		return nil
	}
	uid := uuid.UUID(u.Bytes)
	return &uid
}

// UUIDFrom converts uuid.UUID to pgtype.UUID
func UUIDFrom(u uuid.UUID) pgtype.UUID {
	return pgtype.UUID{Bytes: [16]byte(u), Valid: true}
}

// UUIDFromPtr converts *uuid.UUID to pgtype.UUID
func UUIDFromPtr(u *uuid.UUID) pgtype.UUID {
	if u == nil {
		return pgtype.UUID{Valid: false}
	}
	return pgtype.UUID{Bytes: [16]byte(*u), Valid: true}
}

// ========================================
// Timestamp Conversions
// ========================================

// TimestampTo converts pgtype.Timestamp to time.Time (zero time if invalid)
func TimestampTo(t pgtype.Timestamp) time.Time {
	if !t.Valid {
		return time.Time{}
	}
	return t.Time
}

// TimestampToPtr converts pgtype.Timestamp to *time.Time
func TimestampToPtr(t pgtype.Timestamp) *time.Time {
	if !t.Valid {
		return nil
	}
	return &t.Time
}

// TimestampFrom converts time.Time to pgtype.Timestamp
func TimestampFrom(t time.Time) pgtype.Timestamp {
	if t.IsZero() {
		return pgtype.Timestamp{Valid: false}
	}
	return pgtype.Timestamp{Time: t, Valid: true}
}

// TimestampFromPtr converts *time.Time to pgtype.Timestamp
func TimestampFromPtr(t *time.Time) pgtype.Timestamp {
	if t == nil {
		return pgtype.Timestamp{Valid: false}
	}
	return pgtype.Timestamp{Time: *t, Valid: true}
}

// ========================================
// Integer Conversions (Int4)
// ========================================

// Int4To converts pgtype.Int4 to int32
func Int4To(i pgtype.Int4) int32 {
	if !i.Valid {
		return 0
	}
	return i.Int32
}

// Int4ToPtr converts pgtype.Int4 to *int32
func Int4ToPtr(i pgtype.Int4) *int32 {
	if !i.Valid {
		return nil
	}
	return &i.Int32
}

// Int4From converts int32 to pgtype.Int4
func Int4From(i int32) pgtype.Int4 {
	return pgtype.Int4{Int32: i, Valid: true}
}

// Int4FromPtr converts *int32 to pgtype.Int4
func Int4FromPtr(i *int32) pgtype.Int4 {
	if i == nil {
		return pgtype.Int4{Valid: false}
	}
	return pgtype.Int4{Int32: *i, Valid: true}
}

// Int4ToInt converts pgtype.Int4 to int
func Int4ToInt(i pgtype.Int4) int {
	if !i.Valid {
		return 0
	}
	return int(i.Int32)
}

// IntToInt4 converts int to pgtype.Int4
func IntToInt4(i int) pgtype.Int4 {
	return pgtype.Int4{Int32: int32(i), Valid: true}
}

// ========================================
// Integer Conversions (Int8)
// ========================================

// Int8To converts pgtype.Int8 to int64
func Int8To(i pgtype.Int8) int64 {
	if !i.Valid {
		return 0
	}
	return i.Int64
}

// Int8ToPtr converts pgtype.Int8 to *int64
func Int8ToPtr(i pgtype.Int8) *int64 {
	if !i.Valid {
		return nil
	}
	return &i.Int64
}

// Int8From converts int64 to pgtype.Int8
func Int8From(i int64) pgtype.Int8 {
	return pgtype.Int8{Int64: i, Valid: true}
}

// Int8FromPtr converts *int64 to pgtype.Int8
func Int8FromPtr(i *int64) pgtype.Int8 {
	if i == nil {
		return pgtype.Int8{Valid: false}
	}
	return pgtype.Int8{Int64: *i, Valid: true}
}

// ========================================
// Float Conversions (Float8)
// ========================================

// Float8To converts pgtype.Float8 to float64
func Float8To(f pgtype.Float8) float64 {
	if !f.Valid {
		return 0
	}
	return f.Float64
}

// Float8ToPtr converts pgtype.Float8 to *float64
func Float8ToPtr(f pgtype.Float8) *float64 {
	if !f.Valid {
		return nil
	}
	return &f.Float64
}

// Float8From converts float64 to pgtype.Float8
func Float8From(f float64) pgtype.Float8 {
	return pgtype.Float8{Float64: f, Valid: true}
}

// Float8FromPtr converts *float64 to pgtype.Float8
func Float8FromPtr(f *float64) pgtype.Float8 {
	if f == nil {
		return pgtype.Float8{Valid: false}
	}
	return pgtype.Float8{Float64: *f, Valid: true}
}

// ========================================
// Date Conversions
// ========================================

// DateTo converts pgtype.Date to time.Time (zero time if invalid)
func DateTo(d pgtype.Date) time.Time {
	if !d.Valid {
		return time.Time{}
	}
	return d.Time
}

// DateToPtr converts pgtype.Date to *time.Time
func DateToPtr(d pgtype.Date) *time.Time {
	if !d.Valid {
		return nil
	}
	return &d.Time
}

// DateFrom converts time.Time to pgtype.Date
func DateFrom(t time.Time) pgtype.Date {
	if t.IsZero() {
		return pgtype.Date{Valid: false}
	}
	return pgtype.Date{Time: t, Valid: true}
}

// DateFromPtr converts *time.Time to pgtype.Date
func DateFromPtr(t *time.Time) pgtype.Date {
	if t == nil {
		return pgtype.Date{Valid: false}
	}
	return pgtype.Date{Time: *t, Valid: true}
}

// ========================================
// Numeric Conversions
// ========================================

// NumericToFloat64 converts pgtype.Numeric to float64
func NumericToFloat64(n pgtype.Numeric) float64 {
	if !n.Valid {
		return 0
	}
	f, _ := n.Float64Value()
	return f.Float64
}

// NumericToPtr converts pgtype.Numeric to *float64
func NumericToPtr(n pgtype.Numeric) *float64 {
	if !n.Valid {
		return nil
	}
	f, _ := n.Float64Value()
	return &f.Float64
}

// NumericFrom creates pgtype.Numeric from float64
func NumericFrom(f float64) pgtype.Numeric {
	var n pgtype.Numeric
	_ = n.Scan(f)
	return n
}

// NumericFromPtr creates pgtype.Numeric from *float64
func NumericFromPtr(f *float64) pgtype.Numeric {
	if f == nil {
		return pgtype.Numeric{Valid: false}
	}
	var n pgtype.Numeric
	_ = n.Scan(*f)
	return n
}
