from datetime import datetime
from typing import Dict, Optional
import json


class StructuredEventEmitter:
    """
    Generates metadata-only structured events for telemetry.
    
    Events contain NO raw prompt text - only metadata for analysis:
    - Time bucket (date/hour)
    - Risk category (PII/Health/Finance/Credentials/Normal)
    - Risk score bucket (0-0.2, 0.2-0.5, 0.5-0.8, 0.8-1.0)
    - Action taken (Allow/Warn+Mask/Block)
    - Detector version (v1, v2, v2.1, etc.)
    
    Phase 3 Privacy Preserving Telemetry & Analytics pipeline will collect these events on server-side.
    """

    DETECTOR_VERSION = "v1"  # Initial detector: rules + baseline model

    def __init__(self, detector_version: str = DETECTOR_VERSION):
        self.detector_version = detector_version

    def emit(self, 
             original_text: str,
             enforcement_output: Dict,
             fused_output: Dict,
             timestamp: Optional[datetime] = None) -> Dict:
        """
        Generate structured metadata event.
        
        Args:
            original_text: User's original input (used only for text length, then discarded)
            enforcement_output: Output from EnforcementEngine
            fused_output: Output from FusionEngine
            timestamp: Event timestamp (defaults to now)
        
        Returns:
        {
            "event_id": "unique_uuid",
            "timestamp": "2026-04-23T14:00:00Z",
            "time_bucket": "2026-04-23 14:00",  # hourly bucket
            "date_bucket": "2026-04-23",
            "risk_category": "PII | HEALTH | FINANCE | CREDENTIALS | NORMAL",
            "risk_score": 0.45,  # numeric 0-1
            "risk_score_bucket": "0.2-0.5",
            "action_taken": "ALLOW | WARN_AND_MASK | BLOCK_PROMPT",
            "data_type": "DIRECT_PII | QUASI_PII | AUTH | CONTEXTUAL | NORMAL",
            "detector_version": "v1",
            "metadata": {
                "text_length": 156,
                "entities_detected": ["email", "name"],
                "rule_severity": "HIGH",
                "llm_severity": "MEDIUM",
                "rule_category": "PII",
                "llm_category": "PII",
                "disagreement": false
            }
        }
        """
        if timestamp is None:
            timestamp = datetime.now()
        
        # Generate time buckets
        time_bucket = timestamp.strftime("%Y-%m-%d %H:00")
        date_bucket = timestamp.strftime("%Y-%m-%d")
        iso_timestamp = timestamp.isoformat() + "Z"
        
        # Extract risk score and compute bucket
        raw_score = fused_output.get("raw_score", 0.0)
        risk_score_bucket = self._score_to_bucket(raw_score)
        
        # Map enforcement action to risk exposure category
        risk_category = self._map_to_risk_category(fused_output)
        
        # Collect entities detected (from LLM)
        llm_entities = fused_output.get("llm", {}).get("entities", {})
        entities_detected = [k for k, v in llm_entities.items() if v]
        
        # Check for disagreement between rule and LLM
        rule_cat = fused_output.get("rule", {}).get("category", "NORMAL")
        llm_cat = fused_output.get("llm", {}).get("category", "NORMAL")
        
        # Normalize CREDENTIAL/HEALTH/FINANCIAL to PII for disagreement detection
        rule_cat_normalized = "PII" if rule_cat in ["CREDENTIAL", "HEALTH", "FINANCIAL"] else rule_cat
        llm_cat_normalized = "PII" if llm_cat in ["CREDENTIAL", "HEALTH", "FINANCIAL"] else llm_cat
        
        # Only flag as disagreement if normalized categories differ
        disagreement = rule_cat_normalized != llm_cat_normalized
        
        event = {
            "event_id": self._generate_event_id(timestamp, original_text),
            "timestamp": iso_timestamp,
            "time_bucket": time_bucket,
            "date_bucket": date_bucket,
            "risk_category": risk_category,
            "risk_score": round(raw_score, 3),
            "risk_score_bucket": risk_score_bucket,
            "action_taken": enforcement_output.get("action", "ALLOW"),
            "data_type": fused_output.get("data_type", "NORMAL"),
            "detector_version": self.detector_version,
            "metadata": {
                "text_length": len(original_text),
                "entities_detected": entities_detected,
                "rule_severity": fused_output.get("rule", {}).get("severity", "LOW"),
                "llm_severity": fused_output.get("llm", {}).get("severity", "LOW"),
                "rule_category": rule_cat,
                "llm_category": llm_cat,
                "disagreement": disagreement
            }
        }
        
        return event

    def _map_to_risk_category(self, fused_output: Dict) -> str:
        """
        Map fused output to high-level risk category.
        Future versions can integrate with health/finance detection.
        """
        data_type = fused_output.get("data_type", "NORMAL") # Default to NORMAL if not provided
        llm_cat = fused_output.get("llm", {}).get("category", "NORMAL") # Default to NORMAL if not provided
        
        # For now, simplified mapping
        # Phase 2+ will add HEALTH, FINANCE, CREDENTIALS detection
        if data_type in ["DIRECT_PII", "QUASI_PII"]:
            return "PII"
        elif llm_cat == "CREDENTIAL":
            return "CREDENTIALS"
        elif llm_cat == "FINANCIAL":
            return "FINANCE"
        elif llm_cat == "HEALTH":
            return "HEALTH"
        else:
            return "NORMAL"

    def _score_to_bucket(self, score: float) -> str:
        """Convert numeric risk score (0-1) to bucket."""
        if score < 0.2:
            return "0.0-0.2"
        elif score < 0.5:
            return "0.2-0.5"
        elif score < 0.8:
            return "0.5-0.8"
        else:
            return "0.8-1.0"

    def _generate_event_id(self, timestamp: datetime, text: str) -> str:
        """
        Generate deterministic event ID (for deduplication).
        Uses timestamp + hash of normalized text.
        """
        import hashlib
        # Hash of normalized text (no PII in ID itself)
        text_hash = hashlib.sha256(text.encode()).hexdigest()[:12] 
        time_component = timestamp.strftime("%Y%m%d%H%M%S")
        return f"evt_{time_component}_{text_hash}"

    def serialize(self, event: Dict) -> str:
        """
        Serialize event to JSON for transmission to telemetry collector.
        This is what gets sent to Phase 3 (server-side).
        """
        return json.dumps(event, indent=2)

    def batch_serialize(self, events: list) -> str:
        """
        Serialize multiple events as a batch.
        Useful for batch transmission to telemetry collector.
        """
        return json.dumps({
            "event_batch": events,
            "batch_count": len(events),
            "batch_timestamp": datetime.utcnow().isoformat() + "Z"
        }, indent=2)
