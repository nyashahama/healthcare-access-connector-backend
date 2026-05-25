package forum

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	forumDomain "github.com/nyashahama/healthcare-access-connector-backend/internal/domain/forum"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/middleware"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/service"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

type MockForumRepository struct {
	mock.Mock
}

func (m *MockForumRepository) CreatePost(ctx context.Context, authorID uuid.UUID, req forumDomain.CreatePostRequest) (forumDomain.ForumPost, error) {
	args := m.Called(ctx, authorID, req)
	if args.Get(0) == nil {
		return forumDomain.ForumPost{}, args.Error(1)
	}
	return args.Get(0).(forumDomain.ForumPost), args.Error(1)
}

func (m *MockForumRepository) GetPost(ctx context.Context, postID uuid.UUID) (forumDomain.ForumPost, error) {
	args := m.Called(ctx, postID)
	if args.Get(0) == nil {
		return forumDomain.ForumPost{}, args.Error(1)
	}
	return args.Get(0).(forumDomain.ForumPost), args.Error(1)
}

func (m *MockForumRepository) ListPosts(ctx context.Context, limit, offset int32) ([]forumDomain.ForumPost, int64, error) {
	args := m.Called(ctx, limit, offset)
	if args.Get(0) == nil {
		return nil, 0, args.Error(2)
	}
	return args.Get(0).([]forumDomain.ForumPost), args.Get(1).(int64), args.Error(2)
}

func (m *MockForumRepository) CreateComment(ctx context.Context, postID, authorID uuid.UUID, content string) (forumDomain.ForumComment, error) {
	args := m.Called(ctx, postID, authorID, content)
	if args.Get(0) == nil {
		return forumDomain.ForumComment{}, args.Error(1)
	}
	return args.Get(0).(forumDomain.ForumComment), args.Error(1)
}

func (m *MockForumRepository) ListComments(ctx context.Context, postID uuid.UUID, limit, offset int32) ([]forumDomain.ForumComment, int64, error) {
	args := m.Called(ctx, postID, limit, offset)
	if args.Get(0) == nil {
		return nil, 0, args.Error(2)
	}
	return args.Get(0).([]forumDomain.ForumComment), args.Get(1).(int64), args.Error(2)
}

func (m *MockForumRepository) DeletePost(ctx context.Context, postID, authorID uuid.UUID) error {
	args := m.Called(ctx, postID, authorID)
	return args.Error(0)
}

func (m *MockForumRepository) IncrementView(ctx context.Context, postID uuid.UUID) error {
	args := m.Called(ctx, postID)
	return args.Error(0)
}

func setupTestForumHandler(mockRepo *MockForumRepository) *ForumHandler {
	logger := zerolog.New(nil)
	return NewForumHandler(mockRepo, &logger, 0)
}

func addUserToContextForForum(ctx context.Context, claims *service.TokenClaims) context.Context {
	return context.WithValue(ctx, middleware.UserContextKey, claims)
}

func addPostIDParam(ctx context.Context, postID string) context.Context {
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("postId", postID)
	return context.WithValue(ctx, chi.RouteCtxKey, rctx)
}

func TestForumHandler_DeletePost(t *testing.T) {
	invalidPostID := "not-a-uuid"
	postID := uuid.New()
	ownerID := uuid.New()
	authorID := uuid.New()

	t.Run("unauthenticated", func(t *testing.T) {
		mockRepo := new(MockForumRepository)
		handler := setupTestForumHandler(mockRepo)

		req := httptest.NewRequest(http.MethodDelete, "/forum/posts/"+postID.String(), nil)
		req = req.WithContext(addPostIDParam(req.Context(), postID.String()))

		w := httptest.NewRecorder()
		handler.DeletePost(w, req)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
		mockRepo.AssertExpectations(t)
	})

	t.Run("bad request", func(t *testing.T) {
		mockRepo := new(MockForumRepository)
		handler := setupTestForumHandler(mockRepo)
		claims := &service.TokenClaims{UserID: ownerID, Email: "owner@example.com"}

		req := httptest.NewRequest(http.MethodDelete, "/forum/posts/"+invalidPostID, nil)
		ctx := addUserToContextForForum(req.Context(), claims)
		req = req.WithContext(addPostIDParam(ctx, invalidPostID))

		w := httptest.NewRecorder()
		handler.DeletePost(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		mockRepo.AssertExpectations(t)
	})

	t.Run("not found", func(t *testing.T) {
		mockRepo := new(MockForumRepository)
		handler := setupTestForumHandler(mockRepo)
		claims := &service.TokenClaims{UserID: ownerID, Email: "owner@example.com"}

		mockRepo.On("GetPost", mock.Anything, postID).Return(forumDomain.ForumPost{}, pgx.ErrNoRows).Once()

		req := httptest.NewRequest(http.MethodDelete, "/forum/posts/"+postID.String(), nil)
		ctx := addUserToContextForForum(req.Context(), claims)
		req = req.WithContext(addPostIDParam(ctx, postID.String()))

		w := httptest.NewRecorder()
		handler.DeletePost(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)
		mockRepo.AssertExpectations(t)
	})

	t.Run("forbidden", func(t *testing.T) {
		mockRepo := new(MockForumRepository)
		handler := setupTestForumHandler(mockRepo)
		claims := &service.TokenClaims{UserID: ownerID, Email: "owner@example.com"}
		post := forumDomain.ForumPost{ID: postID, AuthorID: authorID}

		mockRepo.On("GetPost", mock.Anything, postID).Return(post, nil).Once()

		req := httptest.NewRequest(http.MethodDelete, "/forum/posts/"+postID.String(), nil)
		ctx := addUserToContextForForum(req.Context(), claims)
		req = req.WithContext(addPostIDParam(ctx, postID.String()))

		w := httptest.NewRecorder()
		handler.DeletePost(w, req)

		assert.Equal(t, http.StatusForbidden, w.Code)
		mockRepo.AssertNotCalled(t, "DeletePost", mock.Anything, mock.Anything, mock.Anything)
		mockRepo.AssertExpectations(t)
	})

	t.Run("success", func(t *testing.T) {
		mockRepo := new(MockForumRepository)
		handler := setupTestForumHandler(mockRepo)
		claims := &service.TokenClaims{UserID: ownerID, Email: "owner@example.com"}
		post := forumDomain.ForumPost{ID: postID, AuthorID: ownerID}

		mockRepo.On("GetPost", mock.Anything, postID).Return(post, nil).Once()
		mockRepo.On("DeletePost", mock.Anything, postID, ownerID).Return(nil).Once()

		req := httptest.NewRequest(http.MethodDelete, "/forum/posts/"+postID.String(), nil)
		ctx := addUserToContextForForum(req.Context(), claims)
		req = req.WithContext(addPostIDParam(ctx, postID.String()))

		w := httptest.NewRecorder()
		handler.DeletePost(w, req)

		var response map[string]string
		_ = json.NewDecoder(w.Body).Decode(&response)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, "Post deleted", response["message"])
		mockRepo.AssertExpectations(t)
	})
}
