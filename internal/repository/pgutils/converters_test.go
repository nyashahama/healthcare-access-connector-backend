package pgutils

import (
	"math"
	"testing"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/stretchr/testify/require"
)

func TestNumericToFloat64WithInvalidValueReturnsZero(t *testing.T) {
	t.Run("float conversion failure returns zero", func(t *testing.T) {
		var n pgtype.Numeric
		require.Error(t, n.Scan("not-a-number"))

		got := NumericToFloat64(n)
		require.Equal(t, 0.0, got)
	})
}

func TestNumericToPtrWithInvalidValueReturnsNil(t *testing.T) {
	t.Run("float pointer conversion failure returns nil", func(t *testing.T) {
		var n pgtype.Numeric
		require.Error(t, n.Scan("not-a-number"))

		got := NumericToPtr(n)
		require.Nil(t, got)
	})
}

func TestNumericFromInvalidValueReturnsInvalidNumeric(t *testing.T) {
	t.Run("invalid float is rejected", func(t *testing.T) {
		value := math.Inf(1)
		got := NumericFrom(value)
		require.False(t, got.Valid)
	})
}

func TestNumericFromPtrInvalidValueReturnsInvalidNumeric(t *testing.T) {
	t.Run("invalid float pointer is rejected", func(t *testing.T) {
		value := math.Inf(-1)
		got := NumericFromPtr(&value)
		require.False(t, got.Valid)
	})
}

func TestNumericFromReturnsValidNumeric(t *testing.T) {
	t.Run("finite float is accepted", func(t *testing.T) {
		value := 12.75
		got := NumericFrom(value)
		require.True(t, got.Valid)
	})
}

func TestNumericFromPtrReturnsValidNumeric(t *testing.T) {
	t.Run("finite float pointer is accepted", func(t *testing.T) {
		value := 12.75
		got := NumericFromPtr(&value)
		require.True(t, got.Valid)
	})
}
