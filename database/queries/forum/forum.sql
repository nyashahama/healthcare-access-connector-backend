-- name: CreateForumPost :one
INSERT INTO forum_posts (author_id, title, content, category)
VALUES ($1, $2, $3, $4)
RETURNING *;

-- name: GetForumPostByID :one
SELECT fp.*, u.email as author_email, u.role as author_role
FROM forum_posts fp
JOIN users u ON fp.author_id = u.id
WHERE fp.id = $1;

-- name: ListForumPosts :many
SELECT fp.*, u.email as author_email, u.role as author_role,
    (SELECT COUNT(*) FROM forum_comments fc WHERE fc.post_id = fp.id) as comment_count
FROM forum_posts fp
JOIN users u ON fp.author_id = u.id
ORDER BY fp.is_pinned DESC, fp.created_at DESC
LIMIT $1 OFFSET $2;

-- name: CountForumPosts :one
SELECT COUNT(*) FROM forum_posts;

-- name: UpdateForumPost :one
UPDATE forum_posts
SET title = $2, content = $3, category = $4, updated_at = NOW()
WHERE id = $1 AND author_id = $5
RETURNING *;

-- name: DeleteForumPost :exec
DELETE FROM forum_posts WHERE id = $1 AND author_id = $2;

-- name: IncrementForumPostView :exec
UPDATE forum_posts SET view_count = view_count + 1 WHERE id = $1;

-- name: CreateForumComment :one
INSERT INTO forum_comments (post_id, author_id, content)
VALUES ($1, $2, $3)
RETURNING *;

-- name: ListForumComments :many
SELECT fc.*, u.email as author_email, u.role as author_role
FROM forum_comments fc
JOIN users u ON fc.author_id = u.id
WHERE fc.post_id = $1
ORDER BY fc.created_at ASC
LIMIT $2 OFFSET $3;

-- name: CountForumComments :one
SELECT COUNT(*) FROM forum_comments WHERE post_id = $1;

-- name: DeleteForumComment :exec
DELETE FROM forum_comments WHERE id = $1 AND author_id = $2;
