package vuln

import (
	"compress/gzip"
	"context"
	"encoding/csv"
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"
	"time"
)

const epssURL = "https://epss.cyentia.com/epss_scores-current.csv.gz"

// updateEPSSScores downloads the full EPSS CSV and batch-updates all matching vulnerabilities.
func (v *VulnIngestor) updateEPSSScores(ctx context.Context) (int, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", epssURL, nil)
	if err != nil {
		return 0, fmt.Errorf("vuln: epss request: %w", err)
	}

	resp, err := v.httpClient.Do(req)
	if err != nil {
		return 0, fmt.Errorf("vuln: epss fetch: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("vuln: epss status %d", resp.StatusCode)
	}

	gz, err := gzip.NewReader(resp.Body)
	if err != nil {
		return 0, fmt.Errorf("vuln: epss gzip: %w", err)
	}
	defer gz.Close()

	reader := csv.NewReader(gz)
	reader.Comment = '#'
	reader.FieldsPerRecord = -1

	// Skip the header row (cve,epss,percentile).
	if _, err := reader.Read(); err != nil {
		return 0, fmt.Errorf("vuln: epss csv header: %w", err)
	}

	now := time.Now().UTC()
	var totalUpdated int
	const batchSize = 1000

	// Process in batches.
	type epssRow struct {
		cveID      string
		score      float64
		percentile float64
	}

	var batch []epssRow

	flushBatch := func() error {
		if len(batch) == 0 {
			return nil
		}
		tx, err := v.archive.Pool().Begin(ctx)
		if err != nil {
			return fmt.Errorf("vuln: epss begin tx: %w", err)
		}
		defer tx.Rollback(ctx)

		for _, row := range batch {
			_, err := tx.Exec(ctx, `
				UPDATE vulnerabilities
				SET epss_score = $2, epss_percentile = $3, epss_updated_at = $4, updated_at = NOW()
				WHERE cve_id = $1`,
				row.cveID, row.score, row.percentile, now)
			if err != nil {
				return fmt.Errorf("vuln: epss update %s: %w", row.cveID, err)
			}
		}

		if err := tx.Commit(ctx); err != nil {
			return fmt.Errorf("vuln: epss commit: %w", err)
		}
		totalUpdated += len(batch)
		batch = batch[:0]
		return nil
	}

	for {
		if ctx.Err() != nil {
			return totalUpdated, ctx.Err()
		}

		record, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return totalUpdated, fmt.Errorf("vuln: epss csv read: %w", err)
		}

		if len(record) < 3 {
			continue
		}

		score, err := strconv.ParseFloat(record[1], 64)
		if err != nil {
			continue
		}
		percentile, err := strconv.ParseFloat(record[2], 64)
		if err != nil {
			continue
		}

		batch = append(batch, epssRow{
			cveID:      record[0],
			score:      score,
			percentile: percentile,
		})

		if len(batch) >= batchSize {
			if err := flushBatch(); err != nil {
				log.Printf("vuln: epss batch error: %v", err)
				return totalUpdated, err
			}
		}
	}

	// Flush remaining.
	if err := flushBatch(); err != nil {
		return totalUpdated, err
	}

	return totalUpdated, nil
}
