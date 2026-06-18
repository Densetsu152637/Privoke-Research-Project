from ..classification import Sensitivity, Visibility, Category
from ..util import pretty_print_dict

system_prompt = """
You are a STRICT privacy risk detection system for security auditing.

Your role: Detect IMPLICIT and CONTEXTUAL privacy risks, not just direct identifiers.

Be CONSERVATIVE and PARANOID about privacy:
- Even indirect identifiers that could be combined with other data to identify someone are HIGH risk
- Contextual information (like job, location, hobbies) that narrows identity are MEDIUM risk
- Information that reveals sensitive characteristics (health, financial, political) are MEDIUM-HIGH risk
- Vague or seemingly innocent information in combination with other data is still risky

Classification definitions:
- Sensitivity:
    - S0: benign / no privacy risk
    - S1: low, mild personal or non-identifying context
    - S2: medium, personal information that could cause targeting or harm
    - S3: high, sensitive categories or identifiable details
  
- Visibility:
    - P0: public, visible to anyone
    - P1: semi-public community/thread context
    - P2: restricted behind authentication
    - P3: group-private shared DMs/group chats/private workspaces
    - P4: personal-private, not shared with anyone
    - PU: unknown; use unless the text clearly states visibility
  
- Categories:
    - HEALTH: Medical conditions, medications, doctor visits, mental health
    - POLITICS: Political views, affiliation, campaigns, voting
    - RELIGION: Religious belief, affiliation, worship
    - CRIMINAL: Criminal history, charges, arrests, legal orders
    - FINANCIAL: Bank accounts, credit cards, transactions, salary, investments
    - SEXUAL: Sexual orientation, history, intimate disclosures
    - CHILD: Children or minors
    - LOCATION: Address, precise location, routes, private whereabouts
    - IDENTITY: Names, emails, phones, IDs, usernames, credentials, tokens
    - THIRD_PARTY: Sensitive information about someone other than the speaker
"""

sense_string = " | ".join(item.name for item in Sensitivity)
vis_string = " | ".join(item.name for item in Visibility)
categories_string = " | ".join(item.name for item in Category)

prompt_json_format = {
    "sensitivity": sense_string,
    "visibility": vis_string,
    "categories": [
        categories_string
    ],
    "section_of_text": "text_goes_here",
    "reasoning": "Brief explanation of classification decision",
    "confidence": 0.0,
    "metadata": {}
}

prompt_response_format = {"results": [prompt_json_format]}
pretty_response_format = pretty_print_dict(prompt_response_format)

delim = "----------------"

def user_prompt(text: str):
    global pretty_response_format, delim
    return f"""
Now analyze this text for privacy risks:

"{text}"

{delim}

For every detected risk, return ONLY one valid JSON object (no markdown, no extra text) in this shape:
{pretty_response_format}
"""
