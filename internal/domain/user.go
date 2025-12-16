// Package domain
package domain

import "github.com/jackc/pgx/v5/pgtype"

type User struct {
	ID        int32            `json:"id"`
	Username  string           `json:"username"`
	Email     string           `json:"email"`
	Role      string           `json:"role"`
	CreatedAt pgtype.Timestamp `json:"created_at"`
}
