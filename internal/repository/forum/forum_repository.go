package forum

import (
	"context"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	sqlc "github.com/nyashahama/healthcare-access-connector-backend/internal/db"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain/forum"
	"github.com/rs/zerolog"
)

type Repository struct {
	q      *sqlc.Queries
	logger *zerolog.Logger
}

func NewRepository(pool sqlc.DBTX, logger *zerolog.Logger) *Repository {
	return &Repository{q: sqlc.New(pool), logger: logger}
}

func toPgUUID(id uuid.UUID) pgtype.UUID {
	return pgtype.UUID{Bytes: id, Valid: true}
}

func fromPgUUID(pg pgtype.UUID) uuid.UUID {
	if !pg.Valid {
		return uuid.Nil
	}
	return pg.Bytes
}

func fromPgUUIDPtr(pg pgtype.UUID) *uuid.UUID {
	if !pg.Valid {
		return nil
	}
	id := uuid.UUID(pg.Bytes)
	return &id
}

func (r *Repository) CreatePost(ctx context.Context, authorID uuid.UUID, req forum.CreatePostRequest) (forum.ForumPost, error) {
	row, err := r.q.CreateForumPost(ctx, sqlc.CreateForumPostParams{
		AuthorID: toPgUUID(authorID),
		Title:    req.Title,
		Content:  req.Content,
		Category: req.Category,
	})
	if err != nil {
		return forum.ForumPost{}, err
	}
	return forum.ForumPost{
		ID:        fromPgUUID(row.ID),
		AuthorID:  fromPgUUID(row.AuthorID),
		Title:     row.Title,
		Content:   row.Content,
		Category:  row.Category,
		IsPinned:  row.IsPinned.Bool,
		ViewCount: int(row.ViewCount.Int32),
		CreatedAt: row.CreatedAt.Time,
		UpdatedAt: row.UpdatedAt.Time,
	}, nil
}

func (r *Repository) GetPost(ctx context.Context, postID uuid.UUID) (forum.ForumPost, error) {
	row, err := r.q.GetForumPostByID(ctx, toPgUUID(postID))
	if err != nil {
		return forum.ForumPost{}, err
	}
	return forum.ForumPost{
		ID:           fromPgUUID(row.ID),
		AuthorID:     fromPgUUID(row.AuthorID),
		AuthorEmail:  row.AuthorEmail,
		AuthorRole:   row.AuthorRole,
		Title:        row.Title,
		Content:      row.Content,
		Category:     row.Category,
		IsPinned:     row.IsPinned.Bool,
		ViewCount:    int(row.ViewCount.Int32),
		CreatedAt:    row.CreatedAt.Time,
		UpdatedAt:    row.UpdatedAt.Time,
	}, nil
}

func (r *Repository) ListPosts(ctx context.Context, limit, offset int32) ([]forum.ForumPost, int64, error) {
	rows, err := r.q.ListForumPosts(ctx, sqlc.ListForumPostsParams{
		Limit:  limit,
		Offset: offset,
	})
	if err != nil {
		return nil, 0, err
	}
	count, _ := r.q.CountForumPosts(ctx)
	posts := make([]forum.ForumPost, len(rows))
	for i, row := range rows {
		posts[i] = forum.ForumPost{
			ID:           fromPgUUID(row.ID),
			AuthorID:     fromPgUUID(row.AuthorID),
			AuthorEmail:  row.AuthorEmail,
			AuthorRole:   row.AuthorRole,
			Title:        row.Title,
			Content:      row.Content,
			Category:     row.Category,
			IsPinned:     row.IsPinned.Bool,
			ViewCount:    int(row.ViewCount.Int32),
			CommentCount: int(row.CommentCount),
			CreatedAt:    row.CreatedAt.Time,
			UpdatedAt:    row.UpdatedAt.Time,
		}
	}
	return posts, count, nil
}

func (r *Repository) CreateComment(ctx context.Context, postID, authorID uuid.UUID, content string) (forum.ForumComment, error) {
	row, err := r.q.CreateForumComment(ctx, sqlc.CreateForumCommentParams{
		PostID:   toPgUUID(postID),
		AuthorID: toPgUUID(authorID),
		Content:  content,
	})
	if err != nil {
		return forum.ForumComment{}, err
	}
	return forum.ForumComment{
		ID:        fromPgUUID(row.ID),
		PostID:    fromPgUUID(row.PostID),
		AuthorID:  fromPgUUID(row.AuthorID),
		Content:   row.Content,
		CreatedAt: row.CreatedAt.Time,
		UpdatedAt: row.UpdatedAt.Time,
	}, nil
}

func (r *Repository) ListComments(ctx context.Context, postID uuid.UUID, limit, offset int32) ([]forum.ForumComment, int64, error) {
	rows, err := r.q.ListForumComments(ctx, sqlc.ListForumCommentsParams{
		PostID: toPgUUID(postID),
		Limit:  limit,
		Offset: offset,
	})
	if err != nil {
		return nil, 0, err
	}
	count, _ := r.q.CountForumComments(ctx, toPgUUID(postID))
	comments := make([]forum.ForumComment, len(rows))
	for i, row := range rows {
		comments[i] = forum.ForumComment{
			ID:          fromPgUUID(row.ID),
			PostID:      fromPgUUID(row.PostID),
			AuthorID:    fromPgUUID(row.AuthorID),
			AuthorEmail: row.AuthorEmail,
			AuthorRole:  row.AuthorRole,
			Content:     row.Content,
			CreatedAt:   row.CreatedAt.Time,
			UpdatedAt:   row.UpdatedAt.Time,
		}
	}
	return comments, count, nil
}

func (r *Repository) IncrementView(ctx context.Context, postID uuid.UUID) error {
	return r.q.IncrementForumPostView(ctx, toPgUUID(postID))
}
