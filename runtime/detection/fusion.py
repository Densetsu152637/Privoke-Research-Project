class FusionEngine:  # fuses rule + LLM outputs

    def map_data_type(self, rule_result, llm_result, entities):

        if entities.get("email") or entities.get("phone"):
            return "DIRECT_PII", "Contains direct identifiers like email/phone"

        if (entities.get("username") and entities.get("location")) or (entities.get("name") and entities.get("location")):
            return "QUASI_PII", "Combination of identity + location makes it indirectly identifiable"

        if "family" in rule_result.get("signals", ""):
            return "CONTEXTUAL", "Personal life/family information disclosed in context"

        if "identity field" in rule_result.get("signals", ""):
            return "AUTH", "Structured identity metadata detected (e.g. username/name fields)"

        return "NORMAL", "No strong identifiers detected"

    def fuse(self, rule_result, llm_result):

        severity_rank = {"LOW": 1, "MEDIUM": 2, "HIGH": 3}
        inv_rank = {1: "LOW", 2: "MEDIUM", 3: "HIGH"}

        # --------------------
        # RULE severity
        # --------------------
        rule_sev = severity_rank.get(rule_result.get("severity", "LOW"), 1)

        # --------------------
        # LLM severity
        # --------------------
        llm_sev = severity_rank.get(llm_result.get("severity", "LOW"), 1)

        # --------------------
        # ENTITY PARSING
        # --------------------
        entities = llm_result.get("entities", {})
        if not isinstance(entities, dict):
            entities = {}

        email = bool(entities.get("email"))
        phone = bool(entities.get("phone"))
        location = bool(entities.get("location"))
        username = bool(entities.get("username"))
        name = bool(entities.get("name"))

        # --------------------
        # ENTITY BOOST
        # --------------------
        entity_boost = 1

        if email or phone:
            entity_boost = 3
        elif (name and location) or (username and location):
            entity_boost = 3
        elif location or username or name:
            entity_boost = 2

        # --------------------
        # FINAL SCORE
        # --------------------
        raw_score = (rule_sev * 0.5) + (llm_sev * 0.3) + (entity_boost * 0.2)

        final_score = round(raw_score)
        final_score = max(1, min(final_score, 3))

        # --------------------
        # CATEGORY
        # --------------------
        rule_cat = rule_result.get("category", "NORMAL")
        llm_cat = llm_result.get("category", "NORMAL")

        final_category = (
            "PII"
            if rule_cat == "PII" or llm_cat == "PII" or entity_boost >= 3
            else "NORMAL"
        )

        # --------------------
        # DATA TYPE
        # --------------------
        data_type, data_type_reason = self.map_data_type(rule_result, llm_result, entities)

        # dynamic signals (IMPORTANT FIX)
        signals_used = []
        if email or phone:
            signals_used.append("direct_identifier")
        if username:
            signals_used.append("username")
        if name:
            signals_used.append("name")
        if location:
            signals_used.append("location")

        # --------------------
        # RETURN
        # --------------------
        return {
            "category": final_category,
            "severity": inv_rank[final_score],
            "data_type": data_type,
            "data_type_explanation": {
                "reason": data_type_reason,
                "signals_used": signals_used
            },
            "rule": rule_result,
            "llm": llm_result
        }