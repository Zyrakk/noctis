// Package pipeline wires collectors, matcher, analyzer, and dispatch into a
// single streaming data pipeline.
package pipeline

import (
	"context"
	"log"
	"sync"

	"github.com/Zyrakk/noctis/internal/analyzer"
	"github.com/Zyrakk/noctis/internal/collector"
	"github.com/Zyrakk/noctis/internal/config"
	"github.com/Zyrakk/noctis/internal/llm"
	"github.com/Zyrakk/noctis/internal/matcher"
	"github.com/Zyrakk/noctis/internal/models"
)

// DispatchFunc is called for every enriched finding that survives the pipeline.
type DispatchFunc func(models.EnrichedFinding)

// Pipeline orchestrates the flow: collectors -> matcher -> analyzer -> dispatch.
type Pipeline struct {
	collectors []collector.Collector
	matcher    *matcher.Matcher
	analyzer   *analyzer.Analyzer
	dispatch   DispatchFunc
}

// NewPipeline constructs a Pipeline by compiling the matcher rules and
// initialising the LLM analyzer. Returns an error if the rules contain
// invalid regex patterns.
func NewPipeline(
	collectors []collector.Collector,
	rules []config.RuleConfig,
	llmClient llm.LLMClient,
	promptsDir string,
	dispatch DispatchFunc,
) (*Pipeline, error) {
	m, err := matcher.New(rules)
	if err != nil {
		return nil, err
	}

	a := analyzer.New(llmClient, promptsDir)

	return &Pipeline{
		collectors: collectors,
		matcher:    m,
		analyzer:   a,
		dispatch:   dispatch,
	}, nil
}

// Run starts every collector and processes findings until ctx is cancelled or
// all collectors have finished. It blocks until the fan-in channel is drained.
func (p *Pipeline) Run(ctx context.Context) {
	fanIn := make(chan models.Finding, 100)

	var wg sync.WaitGroup

	for _, c := range p.collectors {
		wg.Add(1)
		go func(c collector.Collector) {
			defer wg.Done()

			// Each collector gets its own channel so a slow collector
			// cannot block others.
			collectorCh := make(chan models.Finding, 100)

			// Forwarding goroutine: copies findings from this collector's
			// channel into the shared fan-in channel.
			var fwdWg sync.WaitGroup
			fwdWg.Add(1)
			go func() {
				defer fwdWg.Done()
				for f := range collectorCh {
					select {
					case fanIn <- f:
					case <-ctx.Done():
						return
					}
				}
			}()

			if err := c.Start(ctx, collectorCh); err != nil {
				log.Printf("pipeline: collector %s error: %v", c.Name(), err)
			}

			// Wait for forwarding goroutine to drain the collector channel
			// before signalling the WaitGroup.
			fwdWg.Wait()
		}(c)
	}

	// Close fan-in channel once every collector (and its forwarder) is done.
	go func() {
		wg.Wait()
		close(fanIn)
	}()

	for finding := range fanIn {
		p.processFinding(ctx, finding)
	}
}

// processFinding runs a single finding through the match -> analyze -> dispatch
// stages. LLM errors are logged but never abort the pipeline.
func (p *Pipeline) processFinding(ctx context.Context, finding models.Finding) {
	// 1. Match
	result, matched := p.matcher.Match(finding)
	if !matched {
		log.Printf("pipeline: finding %s dropped (no rule match)", finding.ID)
		return
	}

	// 2. Build enriched finding with match metadata.
	enriched := models.EnrichedFinding{
		Finding:      finding,
		MatchType:    result.MatchType,
		MatchedRules: result.MatchedRules,
		Severity:     result.Severity,
	}

	// 3. Classify via LLM.
	classResult, err := p.analyzer.Classify(ctx, &finding, result.MatchedRules)
	if err != nil {
		log.Printf("pipeline: classify error for %s: %v", finding.ID, err)
	} else {
		enriched.Category = models.Category(classResult.Category)
		enriched.Confidence = classResult.Confidence
	}

	// 4. Drop irrelevant findings.
	if enriched.Category == models.CategoryIrrelevant {
		log.Printf("pipeline: finding %s classified as irrelevant, dropping", finding.ID)
		return
	}

	// 5. Extract IOCs.
	iocs, err := p.analyzer.ExtractIOCs(ctx, &finding)
	if err != nil {
		log.Printf("pipeline: extract IOCs error for %s: %v", finding.ID, err)
	} else {
		enriched.IOCs = iocs
	}

	// 6. Assess severity — upgrade if LLM says higher.
	llmSev, err := p.analyzer.AssessSeverity(ctx, &finding, string(enriched.Category), result.MatchedRules)
	if err != nil {
		log.Printf("pipeline: severity assessment error for %s: %v", finding.ID, err)
	} else if llmSev > enriched.Severity {
		enriched.Severity = llmSev
	}

	// 7. Summarize.
	summary, err := p.analyzer.Summarize(ctx, &finding, string(enriched.Category), enriched.Severity)
	if err != nil {
		log.Printf("pipeline: summarize error for %s: %v", finding.ID, err)
	} else {
		enriched.LLMAnalysis = summary
	}

	// 8. Dispatch.
	p.dispatch(enriched)
}
