import os
from dotenv import load_dotenv
from openai import OpenAI
import json

load_dotenv()

class InternalModelService: # use openai API for privacy risk classification 

    def __init__(self):
        api_key = os.getenv("OPENAI_API_KEY")
        if not api_key:
            raise ValueError("OPENAI_API_KEY not found in environment variables. Please check your .env file.")
        self.client = OpenAI(api_key=api_key)

    def classify(self, text: str): # takes a string and returns LLM privacy risk classsification 

        prompt = f"""
You are a STRICT privacy risk detection system for security auditing.

You must be CONSERVATIVE.

Even indirect identifiers must be considered risky.

Rules:
- Any username = MEDIUM risk
- Any location = MEDIUM risk
- Any real name = MEDIUM risk
- Combination of name + location = HIGH risk
- Social media handle = MEDIUM risk

Return ONLY valid JSON:
{{
  "category": "PII | CREDENTIAL | FINANCIAL | HEALTH | NORMAL",
  "severity": "LOW | MEDIUM | HIGH",
  "entities": {{
    "email": false,
    "phone": false,
    "location": false,
    "username": true,
    "name": false
  }},
  "reason": "short explanation"
}}

Text:
{text}
"""

        response = self.client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[{"role": "user", "content": prompt}],
            response_format={"type": "json_object"}
        )

        content = response.choices[0].message.content.strip()

        try:
            parsed = json.loads(content)
            return json.dumps(parsed)
        except Exception:
            return json.dumps({
                "category": "NORMAL",
                "severity": "LOW",
                "entities": {
                    "email": False,
                    "phone": False,
                    "location": False,
                    "username": False,
                    "name": False
                },
                "reason": "LLM parse failure fallback"
            })