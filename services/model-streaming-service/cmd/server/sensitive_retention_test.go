package main

import (
	"strings"
	"testing"
)

func TestSensitiveRetentionPoliciesCoexistAndFailClosed(t *testing.T) {
	for _, policy := range []string{contextualRetentionGate, contextualRetentionHinge} {
		objective := contextualRetentionGateObjective
		if policy == contextualRetentionHinge {
			objective = contextualRetentionHingeObjective
		}
		meta := map[string]string{contextualOptimizerKey: policy, contextualStrategyKey: contextualFullEncoderStrategy,
			contextualObjectiveKey: objective, contextualCandidateEligibilityKey: contextualRetentionEligibility,
			contextualFullAdamConfigKey: contextualFullAdamConfig, contextualRetentionManifestKey: strings.Repeat("a", 64)}
		if err := validateContextualFullAdamPolicy(meta); err != nil {
			t.Fatal(err)
		}
		for _, key := range []string{contextualObjectiveKey, contextualCandidateEligibilityKey, contextualFullAdamConfigKey, contextualRetentionManifestKey} {
			copy := map[string]string{}
			for k, v := range meta {
				copy[k] = v
			}
			copy[key] = "wrong"
			if err := validateContextualFullAdamPolicy(copy); err == nil {
				t.Fatalf("accepted wrong %s", key)
			}
		}
	}
	if err := validateContextualFullAdamPolicy(map[string]string{contextualRetentionManifestKey: strings.Repeat("a", 64)}); err == nil {
		t.Fatal("accepted orphan retention pin")
	}
	if err := validateContextualFullAdamPolicy(map[string]string{contextualOptimizerKey: contextualFullAdam,
		contextualStrategyKey: contextualFullEncoderStrategy, contextualObjectiveKey: contextualClassBalancedSumDecisionMarginObjective,
		contextualCandidateEligibilityKey: contextualCandidateEligibility, contextualFullAdamConfigKey: contextualFullAdamConfig}); err != nil {
		t.Fatal("old FULL policy changed", err)
	}
}
