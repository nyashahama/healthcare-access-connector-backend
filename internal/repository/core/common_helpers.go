package core

import (
	"fmt"
	"net/netip"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

// Common helper functions used by all repositories

func stringToStringPtr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
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

func pgtypeTextFromStringPtr(s *string) pgtype.Text {
	if s == nil {
		return pgtype.Text{Valid: false}
	}
	return pgtype.Text{String: *s, Valid: true}
}

func pgtypeTextFromString(s string) pgtype.Text {
	if s == "" {
		return pgtype.Text{Valid: false}
	}
	return pgtype.Text{String: s, Valid: true}
}

func pgtypeUUIDToUUID(u pgtype.UUID) uuid.UUID {
	if !u.Valid {
		return uuid.Nil
	}
	return u.Bytes
}

func uuidToPgtypeUUID(u uuid.UUID) pgtype.UUID {
	return pgtype.UUID{Bytes: u, Valid: true}
}

func uuidPtrToPgtypeUUID(u *uuid.UUID) pgtype.UUID {
	if u == nil {
		return pgtype.UUID{Valid: false}
	}
	return pgtype.UUID{Bytes: *u, Valid: true}
}

func pgtypeBoolToBool(b pgtype.Bool) bool {
	if !b.Valid {
		return false
	}
	return b.Bool
}

func boolToPgtypeBool(b bool) pgtype.Bool {
	return pgtype.Bool{Bool: b, Valid: true}
}

func pgtypeTimestampToTimePtr(t pgtype.Timestamp) *time.Time {
	if !t.Valid {
		return nil
	}
	return &t.Time
}

func timeToPgtypeTimestamp(t time.Time) pgtype.Timestamp {
	return pgtype.Timestamp{Time: t, Valid: true}
}

func timePtrToPgtypeTimestamp(t *time.Time) pgtype.Timestamp {
	if t == nil {
		return pgtype.Timestamp{Valid: false}
	}
	return pgtype.Timestamp{Time: *t, Valid: true}
}

func pgtypeInt4ToInt(i pgtype.Int4) int {
	if !i.Valid {
		return 0
	}
	return int(i.Int32)
}

func intToPgtypeInt4(i int) pgtype.Int4 {
	return pgtype.Int4{Int32: int32(i), Valid: true}
}

func intPtrToPgtypeInt4(i *int) pgtype.Int4 {
	if i == nil {
		return pgtype.Int4{Valid: false}
	}
	return pgtype.Int4{Int32: int32(*i), Valid: true}
}

// netipAddrToString converts *netip.Addr to *string
func netipAddrToString(addr *netip.Addr) *string {
	if addr == nil {
		return nil
	}
	s := addr.String()
	return &s
}

// stringToNetipAddr converts *string to *netip.Addr
func stringToNetipAddr(s *string) (*netip.Addr, error) {
	if s == nil {
		return nil, nil
	}
	addr, err := netip.ParseAddr(*s)
	if err != nil {
		return nil, err
	}
	return &addr, nil
}

// Helper function to convert pgtype.Time to *string
func pgtypeTimeToStringPtr(t pgtype.Time) *string {
	if !t.Valid {
		return nil
	}
	// Convert microseconds since midnight to HH:MM:SS format
	hours := t.Microseconds / (3600 * 1_000_000)
	minutes := (t.Microseconds % (3600 * 1_000_000)) / (60 * 1_000_000)
	seconds := (t.Microseconds % (60 * 1_000_000)) / 1_000_000

	s := fmt.Sprintf("%02d:%02d:%02d", hours, minutes, seconds)
	return &s
}

// Helper function to convert *time.Time to pgtype.Time
func timePtrToPgtypeTime(t *time.Time) pgtype.Time {
	if t == nil {
		return pgtype.Time{Valid: false}
	}
	// Get the time components
	hour, min, sec := t.Clock()
	nsec := t.Nanosecond()

	// Calculate microseconds since midnight
	microseconds := (int64(hour)*3600+int64(min)*60+int64(sec))*1_000_000 + int64(nsec)/1000
	return pgtype.Time{Microseconds: microseconds, Valid: true}
}
