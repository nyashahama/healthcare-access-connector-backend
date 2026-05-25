package forum

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"
	"github.com/google/uuid"
	forumDomain "github.com/nyashahama/healthcare-access-connector-backend/internal/domain/forum"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/handler"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/middleware"
	forumRepo "github.com/nyashahama/healthcare-access-connector-backend/internal/repository/forum"
	"github.com/rs/zerolog"
)

type ForumHandler struct {
	repo    *forumRepo.Repository
	logger  *zerolog.Logger
	timeout time.Duration
}

func NewForumHandler(repo *forumRepo.Repository, logger *zerolog.Logger, timeout time.Duration) *ForumHandler {
	return &ForumHandler{repo: repo, logger: logger, timeout: timeout}
}

func (h *ForumHandler) RegisterRoutes(r chi.Router) {
	r.Post("/posts", h.CreatePost)
	r.Get("/posts", h.ListPosts)
	r.Get("/posts/{postId}", h.GetPost)
	r.Delete("/posts/{postId}", h.DeletePost)
	r.Post("/posts/{postId}/comments", h.CreateComment)
	r.Get("/posts/{postId}/comments", h.ListComments)
}

func getUserID(r *http.Request) (uuid.UUID, bool) {
	claims, ok := middleware.GetUserFromContext(r.Context())
	if !ok {
		return uuid.Nil, false
	}
	return claims.UserID, true
}

func (h *ForumHandler) CreatePost(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	userID, ok := getUserID(r)
	if !ok {
		handler.RespondJSON(w, http.StatusUnauthorized, map[string]string{"error": "Not authenticated"})
		return
	}

	var req forumDomain.CreatePostRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid request body"})
		return
	}
	if req.Title == "" || req.Content == "" {
		handler.RespondJSON(w, http.StatusBadRequest, map[string]string{"error": "Title and content are required"})
		return
	}
	if req.Category == "" {
		req.Category = "general"
	}

	post, err := h.repo.CreatePost(ctx, userID, req)
	if err != nil {
		h.logger.Error().Err(err).Msg("Failed to create forum post")
		handler.RespondJSON(w, http.StatusInternalServerError, map[string]string{"error": "Failed to create post"})
		return
	}

	handler.RespondJSON(w, http.StatusCreated, post)
}

func (h *ForumHandler) ListPosts(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	limitStr := r.URL.Query().Get("limit")
	offsetStr := r.URL.Query().Get("offset")

	limit := int32(20)
	offset := int32(0)
	if v, err := strconv.Atoi(limitStr); err == nil && v > 0 && v <= 100 {
		limit = int32(v)
	}
	if v, err := strconv.Atoi(offsetStr); err == nil && v >= 0 {
		offset = int32(v)
	}

	posts, count, err := h.repo.ListPosts(ctx, limit, offset)
	if err != nil {
		h.logger.Error().Err(err).Msg("Failed to list forum posts")
		handler.RespondJSON(w, http.StatusInternalServerError, map[string]string{"error": "Failed to list posts"})
		return
	}

	handler.RespondJSON(w, http.StatusOK, map[string]interface{}{
		"posts": posts,
		"count": count,
		"limit": limit,
		"offset": offset,
	})
}

func (h *ForumHandler) GetPost(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	postID, err := uuid.Parse(chi.URLParam(r, "postId"))
	if err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid post ID"})
		return
	}

	post, err := h.repo.GetPost(ctx, postID)
	if err != nil {
		handler.RespondJSON(w, http.StatusNotFound, map[string]string{"error": "Post not found"})
		return
	}

	_ = h.repo.IncrementView(ctx, postID)

	handler.RespondJSON(w, http.StatusOK, post)
}

func (h *ForumHandler) DeletePost(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	userID, ok := getUserID(r)
	if !ok {
		handler.RespondJSON(w, http.StatusUnauthorized, map[string]string{"error": "Not authenticated"})
		return
	}

	postID, err := uuid.Parse(chi.URLParam(r, "postId"))
	if err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid post ID"})
		return
	}

	post, err := h.repo.GetPost(ctx, postID)
	if err != nil {
		if err == pgx.ErrNoRows {
			handler.RespondJSON(w, http.StatusNotFound, map[string]string{"error": "Post not found"})
			return
		}
		h.logger.Error().Err(err).Msg("Failed to lookup forum post for deletion")
		handler.RespondJSON(w, http.StatusInternalServerError, map[string]string{"error": "Failed to delete post"})
		return
	}

	if post.AuthorID != userID {
		handler.RespondJSON(w, http.StatusForbidden, map[string]string{"error": "You can only delete your own posts"})
		return
	}

	if err := h.repo.DeletePost(ctx, postID, userID); err != nil {
		h.logger.Error().Err(err).Msg("Failed to delete forum post")
		handler.RespondJSON(w, http.StatusInternalServerError, map[string]string{"error": "Failed to delete post"})
		return
	}

	handler.RespondJSON(w, http.StatusOK, map[string]string{"message": "Post deleted"})
}

func (h *ForumHandler) CreateComment(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	userID, ok := getUserID(r)
	if !ok {
		handler.RespondJSON(w, http.StatusUnauthorized, map[string]string{"error": "Not authenticated"})
		return
	}

	postID, err := uuid.Parse(chi.URLParam(r, "postId"))
	if err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid post ID"})
		return
	}

	var req forumDomain.CreateCommentRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid request body"})
		return
	}
	if req.Content == "" {
		handler.RespondJSON(w, http.StatusBadRequest, map[string]string{"error": "Content is required"})
		return
	}

	comment, err := h.repo.CreateComment(ctx, postID, userID, req.Content)
	if err != nil {
		h.logger.Error().Err(err).Msg("Failed to create comment")
		handler.RespondJSON(w, http.StatusInternalServerError, map[string]string{"error": "Failed to create comment"})
		return
	}
	_ = comment
	handler.RespondJSON(w, http.StatusCreated, comment)
}

func (h *ForumHandler) ListComments(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	postID, err := uuid.Parse(chi.URLParam(r, "postId"))
	if err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid post ID"})
		return
	}

	comments, count, err := h.repo.ListComments(ctx, postID, 100, 0)
	if err != nil {
		h.logger.Error().Err(err).Msg("Failed to list comments")
		handler.RespondJSON(w, http.StatusInternalServerError, map[string]string{"error": "Failed to list comments"})
		return
	}

	handler.RespondJSON(w, http.StatusOK, map[string]interface{}{
		"comments": comments,
		"count":    count,
	})
}
