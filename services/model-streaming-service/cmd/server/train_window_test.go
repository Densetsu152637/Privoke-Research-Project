package main

import (
	"strings"
	"testing"
)

func TestWindowPolicyRequiresExactConfigurationAndIndependentPins(t *testing.T) {
	metadata := map[string]string{contextualOptimizerKey: contextualWindowAdam, contextualStrategyKey: contextualFullEncoderStrategy,
		contextualObjectiveKey: contextualClassBalancedSumDecisionMarginObjective, contextualCandidateEligibilityKey: contextualWindowEligibility,
		contextualWindowConfigKey: contextualWindowConfig, contextualWindowManifestKey: strings.Repeat("a", 64), contextualComponentManifestKey: strings.Repeat("b", 64)}
	if err := validateContextualFullAdamPolicy(metadata); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{contextualWindowConfigKey, contextualWindowManifestKey, contextualComponentManifestKey, contextualCandidateEligibilityKey} {
		altered := map[string]string{}
		for k, v := range metadata {
			altered[k] = v
		}
		delete(altered, key)
		if err := validateContextualFullAdamPolicy(altered); err == nil {
			t.Fatalf("accepted missing %s", key)
		}
	}
	metadata[contextualFullAdamConfigKey] = contextualFullAdamConfig
	if err := validateContextualFullAdamPolicy(metadata); err == nil {
		t.Fatal("accepted legacy/new mixture")
	}
	if err := validateContextualFullAdamPolicy(map[string]string{contextualWindowManifestKey: strings.Repeat("a", 64)}); err == nil {
		t.Fatal("accepted orphan window pin")
	}
}
