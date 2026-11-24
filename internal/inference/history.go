package inference

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// JobSummary exposes durable execution state only. A succeeded historical job
// still needs Job's evidence revalidation before its result can be displayed.
type JobSummary struct {
	ID        string    `json:"id"`
	Function  Function  `json:"function_id"`
	CreatedAt time.Time `json:"created_at"`
	State     string    `json:"state"`
}

type JobPage struct {
	Jobs       []JobSummary `json:"jobs"`
	NextCursor string       `json:"next_cursor,omitempty"`
}

type jobCursor struct {
	CreatedAt time.Time `json:"created_at"`
	ID        string    `json:"id"`
}

func (s Store) ListJobs(ctx context.Context, actor, cursor string, limit int) (JobPage, error) {
	page := JobPage{Jobs: []JobSummary{}}
	if actor == "" || limit < 1 || limit > 100 || len(cursor) > 256 {
		return page, ErrInvalid
	}
	var after jobCursor
	if cursor != "" {
		raw, err := base64.RawURLEncoding.Strict().DecodeString(cursor)
		if err != nil || Strict(raw, &after) != nil || after.CreatedAt.IsZero() || after.CreatedAt.Year() < 1 || after.CreatedAt.Year() > 9999 {
			return page, ErrInvalid
		}
		id, err := uuid.Parse(after.ID)
		if err != nil || id.String() != after.ID {
			return page, ErrInvalid
		}
	}
	c, err := pgx.Connect(ctx, s.DSN)
	if err != nil {
		return page, err
	}
	defer c.Close(context.Background())
	if cursor != "" {
		// An anchor must belong to this actor. Foreign, fabricated and malformed
		// cursors all fail closed without exposing another actor's history.
		var owned bool
		err = c.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM noctis_v2.ai_jobs WHERE actor=$1 AND id=$2 AND created_at=$3)`, actor, after.ID, after.CreatedAt).Scan(&owned)
		if err != nil {
			return page, err
		}
		if !owned {
			return page, ErrInvalid
		}
	}
	query := `SELECT id::text,function_id,created_at,state FROM noctis_v2.ai_jobs WHERE actor=$1`
	args := []any{actor, limit + 1}
	if cursor != "" {
		query += ` AND (created_at,id)<($3,$4::uuid)`
		args = append(args, after.CreatedAt, after.ID)
	}
	rows, err := c.Query(ctx, query+` ORDER BY created_at DESC,id DESC LIMIT $2`, args...)
	if err != nil {
		return page, err
	}
	defer rows.Close()
	for rows.Next() {
		var j JobSummary
		if err = rows.Scan(&j.ID, &j.Function, &j.CreatedAt, &j.State); err != nil {
			return page, err
		}
		page.Jobs = append(page.Jobs, j)
	}
	if err = rows.Err(); err != nil {
		return page, err
	}
	if len(page.Jobs) > limit {
		page.Jobs = page.Jobs[:limit]
		last := page.Jobs[len(page.Jobs)-1]
		raw, _ := json.Marshal(jobCursor{CreatedAt: last.CreatedAt, ID: last.ID})
		page.NextCursor = base64.RawURLEncoding.EncodeToString(raw)
	}
	return page, nil
}
