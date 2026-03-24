package processor

import (
	"context"
	"fmt"
	"log"
	"strings"

	"github.com/Zyrakk/noctis/internal/analyzer"
	"github.com/Zyrakk/noctis/internal/archive"
	"github.com/Zyrakk/noctis/internal/models"
	"github.com/Zyrakk/noctis/internal/modules"
)

// GraphBridge creates entity graph nodes and edges from extracted IOCs and
// LLM-extracted named entities. Non-AI, but still tracked.
type GraphBridge struct {
	archive *archive.Store
	status  *modules.StatusTracker
}

func NewGraphBridge(archiveStore *archive.Store) *GraphBridge {
	g := &GraphBridge{
		archive: archiveStore,
		status:  modules.NewStatusTracker(modules.ModGraphBridge, "Graph Bridge", "processor"),
	}
	g.status.SetEnabled(true)
	return g
}

// BridgeIOCs creates entity graph nodes and edges from extracted IOCs.
// Each IOC becomes a graph entity linked to the source entity.
func (g *GraphBridge) BridgeIOCs(ctx context.Context, entry archive.RawContent, iocs []models.IOC) error {
	// Map IOC types to entity graph types.
	iocEntityType := func(iocType string) string {
		switch iocType {
		case "ip":
			return "ip"
		case "domain":
			return "domain"
		case "hash_md5", "hash_sha1", "hash_sha256":
			return "hash"
		case "cve":
			return "cve"
		case "url":
			return "url"
		case "email":
			return "email"
		default:
			return "ioc"
		}
	}

	// Upsert source entity.
	sourceName := entry.SourceName
	if sourceName == "" {
		sourceName = entry.SourceID
	}
	sourceEntityID := fmt.Sprintf("source:%s", sourceName)
	sourceProps := map[string]any{
		"name":        sourceName,
		"source_type": entry.SourceType,
	}
	if err := g.archive.UpsertEntity(ctx, sourceEntityID, "channel", sourceProps); err != nil {
		log.Printf("processor: graph bridge: upsert source entity: %v", err)
	}

	// Upsert each IOC as an entity and create an edge to the source.
	for _, ioc := range iocs {
		entityID := fmt.Sprintf("ioc:%s:%s", ioc.Type, ioc.Value)
		entityType := iocEntityType(ioc.Type)
		props := map[string]any{
			"value": ioc.Value,
		}
		if ioc.Context != "" {
			props["context"] = ioc.Context
		}

		if err := g.archive.UpsertEntity(ctx, entityID, entityType, props); err != nil {
			log.Printf("processor: graph bridge: upsert ioc entity: %v", err)
			continue
		}

		// Edge: IOC → source (found_in)
		edgeID := fmt.Sprintf("edge:%s:%s:found_in", entityID, sourceEntityID)
		if err := g.archive.UpsertEdge(ctx, edgeID, entityID, sourceEntityID, "found_in"); err != nil {
			log.Printf("processor: graph bridge: upsert edge: %v", err)
		}
	}

	g.status.RecordSuccess()
	return nil
}

// BridgeEntities creates entity graph nodes and edges from LLM-extracted
// named entities (actors, malware, campaigns) and their relationships.
// It respects the observed flag and confidence level to prevent false graph pollution.
func (g *GraphBridge) BridgeEntities(ctx context.Context, entry archive.RawContent, result *analyzer.EntityExtractionResult) error {
	if result == nil {
		return nil
	}

	// Build a name->ID map and name->observed map for relationship resolution.
	nameToID := make(map[string]string)
	nameObserved := make(map[string]bool)

	for _, ent := range result.Entities {
		if ent.Name == "" {
			continue
		}

		// Skip low-confidence entities entirely.
		if ent.Confidence == "low" {
			log.Printf("processor: graph bridge: skipping low-confidence entity %q", ent.Name)
			continue
		}

		entityID := fmt.Sprintf("entity:%s:%s", ent.Type, strings.ToLower(strings.ReplaceAll(ent.Name, " ", "_")))
		props := map[string]any{
			"name": ent.Name,
		}
		if len(ent.Aliases) > 0 {
			props["aliases"] = ent.Aliases
		}
		if ent.Observed {
			props["observed"] = true
		}
		// Mark medium-confidence entities for review.
		if ent.Confidence == "medium" {
			props["needs_review"] = true
		}

		if err := g.archive.UpsertEntity(ctx, entityID, ent.Type, props); err != nil {
			log.Printf("processor: graph bridge: upsert llm entity: %v", err)
			continue
		}
		nameToID[ent.Name] = entityID
		nameObserved[ent.Name] = ent.Observed

		// Also link this entity to the source channel.
		sourceName := entry.SourceName
		if sourceName == "" {
			sourceName = entry.SourceID
		}
		sourceEntityID := fmt.Sprintf("source:%s", sourceName)
		edgeID := fmt.Sprintf("edge:%s:%s:mentioned_in", entityID, sourceEntityID)
		g.archive.UpsertEdge(ctx, edgeID, entityID, sourceEntityID, "mentioned_in")
	}

	// Create relationship edges between named entities.
	for _, rel := range result.Relationships {
		srcID, srcOK := nameToID[rel.Source]
		tgtID, tgtOK := nameToID[rel.Target]
		if !srcOK || !tgtOK || rel.Relationship == "" {
			continue
		}

		// Safety net: if neither entity is observed, force weak relationship.
		relType := rel.Relationship
		if !nameObserved[rel.Source] && !nameObserved[rel.Target] {
			if relType != "referenced_in" && relType != "mentioned_in" {
				relType = "referenced_in"
			}
		}

		edgeID := fmt.Sprintf("edge:%s:%s:%s", srcID, tgtID, relType)
		if err := g.archive.UpsertEdge(ctx, edgeID, srcID, tgtID, relType); err != nil {
			log.Printf("processor: graph bridge: upsert llm edge: %v", err)
		}
	}

	g.status.RecordSuccess()
	return nil
}

func (g *GraphBridge) Status() modules.ModuleStatus { return g.status.Status() }
