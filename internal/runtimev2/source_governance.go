package runtimev2

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// currentQuestionPolicyTx resolves server-owned identity and revision. Callers
// hold the projection guard, which also serializes question edits.
func currentQuestionPolicyTx(ctx context.Context, tx pgx.Tx, question string) (string, int64, error) {
	var revision int64
	if e := tx.QueryRow(ctx, `SELECT revision FROM noctis_v2.questions WHERE id::text=$1`, question).Scan(&revision); e != nil {
		if errors.Is(e, pgx.ErrNoRows) {
			return "", 0, reject(400, "question_not_found")
		}
		return "", 0, e
	}
	version := "question:" + question
	if revision > 1 {
		version = fmt.Sprintf("%s:r%d", version, revision)
	}
	return version, revision, nil
}

func resolveSourceGovernanceTx(ctx context.Context, tx pgx.Tx, source, current string, in operationInput) (string, string, error) {
	version := in.PolicyVersion
	if version == "" {
		// A pause/resume does not implicitly change the governing relationship.
		var question string
		if e := tx.QueryRow(ctx, `SELECT COALESCE((SELECT question_id::text FROM noctis_v2.question_sources WHERE source_id::text=$1),'')`, source).Scan(&question); e != nil {
			return "", "", e
		}
		if in.QuestionID != "" && in.QuestionID != question {
			return "", "", reject(400, "question_policy_mismatch")
		}
		version = current
	}
	var question string
	if strings.HasPrefix(version, "question:") {
		pieces := strings.Split(version, ":")
		id, e := uuid.Parse(pieces[1])
		if e != nil {
			return "", "", reject(400, "invalid_question_policy")
		}
		question = id.String()
		if in.QuestionID != "" && in.QuestionID != question {
			return "", "", reject(400, "question_policy_mismatch")
		}
		canonical, revision, e := currentQuestionPolicyTx(ctx, tx, question)
		if e != nil {
			return "", "", e
		}
		if version != canonical {
			return "", "", &operationError{409, "stale_question_policy", revision}
		}
	} else if in.QuestionID != "" {
		return "", "", reject(400, "question_policy_mismatch")
	}
	var exists bool
	if e := tx.QueryRow(ctx, `SELECT EXISTS(SELECT FROM noctis_v2.policies WHERE version=$1)`, version).Scan(&exists); e != nil {
		return "", "", e
	}
	if !exists {
		return "", "", reject(400, "policy_not_found")
	}
	return version, question, nil
}

// question_sources describes current governance, not historical provenance.
// Retaining the same relationship preserves its independence metadata.
func replaceSourceGovernanceTx(ctx context.Context, tx pgx.Tx, source, question string) error {
	if question == "" {
		_, e := tx.Exec(ctx, `DELETE FROM noctis_v2.question_sources WHERE source_id::text=$1`, source)
		return e
	}
	_, e := tx.Exec(ctx, `INSERT INTO noctis_v2.question_sources(question_id,source_id) VALUES($1,$2) ON CONFLICT(source_id) DO UPDATE SET question_id=excluded.question_id,independence='unknown' WHERE noctis_v2.question_sources.question_id<>excluded.question_id`, question, source)
	return e
}
