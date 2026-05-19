package forum

import (
	"time"

	"github.com/google/uuid"
)

type ForumPost struct {
	ID           uuid.UUID  `json:"id"`
	AuthorID     uuid.UUID  `json:"author_id"`
	AuthorEmail  string     `json:"author_email,omitempty"`
	AuthorRole   string     `json:"author_role,omitempty"`
	Title        string     `json:"title"`
	Content      string     `json:"content"`
	Category     string     `json:"category"`
	IsPinned     bool       `json:"is_pinned"`
	ViewCount    int        `json:"view_count"`
	CommentCount int        `json:"comment_count,omitempty"`
	CreatedAt    time.Time  `json:"created_at"`
	UpdatedAt    time.Time  `json:"updated_at"`
}

type ForumComment struct {
	ID          uuid.UUID `json:"id"`
	PostID      uuid.UUID `json:"post_id"`
	AuthorID    uuid.UUID `json:"author_id"`
	AuthorEmail string    `json:"author_email,omitempty"`
	AuthorRole  string    `json:"author_role,omitempty"`
	Content     string    `json:"content"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

type CreatePostRequest struct {
	Title    string `json:"title"`
	Content  string `json:"content"`
	Category string `json:"category"`
}

type CreateCommentRequest struct {
	Content string `json:"content"`
}
