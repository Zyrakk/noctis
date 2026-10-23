package main

import (
	"github.com/Zyrakk/noctis/internal/inference"
	"testing"
)

func TestQuarantinedEvaluationRejectsAmbiguousFunctionTargets(t *testing.T) {
	identity := []inference.Function{"identity.disambiguate"}
	semantic := []inference.Function{"semantic.classify", "semantic.relevance", "semantic.claims", "semantic.entities_relations", "semantic.observable_roles"}
	groups := map[string][]inference.Function{"semantic-old": semantic, "identity-newer": identity}
	if id, err := resolveQuarantinedFunctions(groups, nil, semantic); err != nil || id != "semantic-old" {
		t.Fatal("semantic resolution used quarantine order", id, err)
	}
	if id, err := resolveQuarantinedFunctions(groups, nil, identity); err != nil || id != "identity-newer" {
		t.Fatal("identity resolution used quarantine count", id, err)
	}
	if _, err := resolveQuarantinedFunctions(groups, map[string]bool{"identity-newer": true}, identity); err == nil {
		t.Fatal("unsafe actor/job state accepted")
	}
	groups["identity-second"] = identity
	if _, err := resolveQuarantinedFunctions(groups, nil, identity); err == nil {
		t.Fatal("ambiguous identity target accepted")
	}
	delete(groups, "identity-second")
	groups["semantic-old"] = semantic[:4]
	if _, err := resolveQuarantinedFunctions(groups, nil, semantic); err == nil {
		t.Fatal("partial semantic group accepted")
	}
	groups["semantic-old"] = append(append([]inference.Function{}, semantic...), "query.plan")
	if _, err := resolveQuarantinedFunctions(groups, nil, semantic); err == nil {
		t.Fatal("mixed function group accepted")
	}
}
