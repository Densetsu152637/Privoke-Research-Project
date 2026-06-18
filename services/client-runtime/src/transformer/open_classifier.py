
import os
import json
from typing import List
from dotenv import load_dotenv
from openai import OpenAI
from .prompt import system_prompt, user_prompt
from .abs_classifier import AbstractClassifier
from ..classification import ClassificationResult, build_results

load_dotenv()

class OpenClassifier(AbstractClassifier):
    """
    Semantic privacy risk classifier using OpenAI API.
    Detects implicit identifiers, contextual risks, and indirect privacy threats.
    """

    def __init__(self):
        """Initialize OpenAI client with API key from environment."""
        api_key = os.getenv("OPENAI_API_KEY")
        if not api_key:
            raise ValueError(
                "OPENAI_API_KEY not found in environment variables. "
                "Please set OPENAI_API_KEY in your .env file."
            ) 
        self.client = OpenAI(api_key=api_key)

    def classify(self, text: str) -> List[ClassificationResult]:
        response = self.client.chat.completions.create(
            model="gpt-4o-mini",
            messages = [
                {
                    "role": "system", 
                    "content": system_prompt
                },
                {
                    "role": "user", 
                    "content": user_prompt(text)
                }
            ],
            response_format = {
                "type": "json_object"
            },
            temperature = 0.25,  # Lower temperature for consistency
            max_tokens = 512
        )

        content = response.choices[0].message.content.strip()

        return build_results(json.loads(content))
