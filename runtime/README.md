# PriVoke Runtime

The core detection pipeline for privacy risk identification and classification.

## Setup

1. **Install dependencies:**
```bash
# From project root:
pip install -r runtime/requirements.txt

# Or if you're already in the runtime/ directory:
pip install -r requirements.txt
```

2. **Configure environment variables:**
   - Copy `.env.example` to `.env` in the project root
   - Add your OpenAI API key:
   ```
   OPENAI_API_KEY=sk-your-key-here
   ```
   - Note: `.env` is not tracked by git (listed in `.gitignore`) and must be created locally

## Structure

- **`main.py`** - Main pipeline runner that orchestrates the detection flow
- **`detection/`** - Detection engines
  - `llm_classifier.py` - LLM-based semantic privacy risk classification
  - `rule_detector.py` - Rule-based pattern detection
  - `fusion.py` - Fusion engine combining multiple detection methods
- **`preprocessing/`** - Data preprocessing
  - `normalizer.py` - Text normalization

## Running the Pipeline

```bash
python main.py
```

This executes the PriVoke detection pipeline which:
1. Loads text samples from Hugging Face PANORAMA dataset
2. **Normalizes** text using TextNormalizer
3. **Rule detection** with pattern matching
4. **LLM classification** using GPT-4o-mini for semantic analysis
5. **Fusion** combining results from multiple detection methods

## Environment Variables

- `OPENAI_API_KEY` - Required for LLM-based classification

## Dependencies

- `openai` - OpenAI API client
- `python-dotenv` - Load environment variables from `.env`
- `datasets` - Hugging Face Datasets
- `huggingface_hub` - Hugging Face Hub access
