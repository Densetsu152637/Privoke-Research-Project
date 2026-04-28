import re # regular expression module for patern matching

def bump(sev, new_sev): # compares two severity levels and returns the higher one (LOW < MEDIUM < HIGH)
        rank = {"LOW": 1, "MEDIUM": 2, "HIGH": 3} # maps severity levels to numeric values 
        inv = {1: "LOW", 2: "MEDIUM", 3: "HIGH"} # inverse mapping to convert back to severity levels
        return inv[max(rank[sev], rank[new_sev])] # returns the higher severity level by comparing the current severity with the new severity and returning the one with the higher rank

class RuleDetector:

    def analyze(self, text: str): # takes a string and returns detection results 

        category = "NORMAL" # initialises category as non-risky 
        severity = "LOW"
        reasons = []

        # EMAIL
        if re.search(r'\b[\w\.-]+@[\w\.-]+\.\w+\b', text): # regex search for email pattern 
            category = "PII"
            severity = "HIGH"
            reasons.append("email detected")

        # PHONE / ID
        if re.search(r'\b(\+?\d{1,3}[- ]?)?\d{8,12}\b', text):
            category = "PII"
            severity = "HIGH"
            reasons.append("phone/ID detected")

        # explicit structured fields
        if re.search(r'\b(location|username|name|user)\s*:\s*', text.lower()):
            category = "PII"
            severity = bump(severity, "MEDIUM")
            reasons.append("identity field detected")

        # Date/Timestamp
        if re.search(r'\b(timestamp|visited|date)\s*:\s*', text.lower()): 
            category = "PII"
            severity = bump(severity, "MEDIUM")
            reasons.append("metadata detected")

        # long narrative
        if len(text.split()) > 80:
            category = "PII"
            severity = bump(severity, "LOW")
            reasons.append("long personal narrative")

        # family
        if re.search(r'\b(married|wife|husband|children|kids|family)\b', text.lower()):
            category = "PII"
            severity = bump(severity, "MEDIUM")
            reasons.append("family disclosure")

        return category, severity, ", ".join(reasons) if reasons else "no rule match"