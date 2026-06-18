
### 3. The Detailed Way: Tokenizer + Model (AutoClasses)

import torch
from transformers import AutoTokenizer, AutoModelForCausalLM

model_id = "HuggingFaceTB/SmolLM2-135M-Instruct"

# 1. Load the tokenizer and model weights
tokenizer = AutoTokenizer.from_pretrained(model_id)
model = AutoModelForCausalLM.from_pretrained(model_id)

# 2. Convert text into tensor tokens
prompt = "Write a Python function to reverse a string."
inputs = tokenizer(prompt, return_tensors="pt") # "pt" specifies PyTorch tensors

# 3. Generate tokens using the model
with torch.no_grad(): # Disable gradient tracking to save memory
    outputs = model.generate(**inputs, max_new_tokens=60, temperature=0.7)

# 4. Decode the numeric tokens back to readable text
decoded_output = tokenizer.decode(outputs[0], skip_special_tokens=True)
print(decoded_output)

### 4. Running Models on GPU (Hardware Acceleration)

# Check if a GPU is available, otherwise default to CPU
device = "cuda" if torch.cuda.is_available() else "cpu"

# Move the model to the target device
model = AutoModelForCausalLM.from_pretrained(model_id).to(device)

# Ensure input tensors are also sent to the exact same device
inputs = tokenizer(prompt, return_tensors="pt").to(device)

outputs = model.generate(**inputs, max_new_tokens=50)

### The Alternative: Building From Scratch

from transformers import AutoConfig, AutoModelForCausalLM

# Load the architecture layout only (randomly initialized weights)
config = AutoConfig.from_pretrained("HuggingFaceTB/SmolLM2-135M-Instruct")
blank_model = AutoModelForCausalLM.from_config(config)

# This model is completely untrained and will output gibberish until you train it
print(blank_model)

### Step-by-Step Architecture for Continuous Training

import torch
from datasets import load_dataset, concatenate_datasets
from transformers import AutoModelForCausalLM, AutoTokenizer, TrainingArguments
from trl import SFTTrainer
from peft import LoraConfig, get_peft_model

model_id = "HuggingFaceTB/SmolLM2-135M-Instruct"
adapter_path = "./casper_pii_lora"

tokenizer = AutoTokenizer.from_pretrained(model_id)
tokenizer.pad_token = tokenizer.eos_token

# 1. Load the Core Model with the existing LoRA Adapter
model = AutoModelForCausalLM.from_pretrained(model_id, device_map="auto", torch_dtype=torch.bfloat16)
try:
    # Load existing adapter if it exists from previous cycles
    model = PeftModel.from_pretrained(model, adapter_path, is_trainable=True)
    print("Loaded existing Casper PII adapter weights.")
except:
    # First-time setup: Initialize new LoRA config
    peft_config = LoraConfig(
        r=16, lora_alpha=32, target_modules=["q_proj", "v_proj"],
        lora_dropout=0.05, bias="none", task_type="CAUSAL_LM"
    )
    model = get_peft_model(model, peft_config)

# 2. Rehearsal Strategy: Mix New Data with Golden Historical Data
new_data = load_dataset("json", data_files="incoming_batch_pii.json", split="train")
golden_buffer = load_dataset("json", data_files="golden_rehearsal_buffer.json", split="train")

# Combine datasets to prevent catastrophic forgetting
combined_dataset = concatenate_datasets([new_data, golden_buffer]).shuffle(seed=42)

# 3. Continuous Training Arguments (Low Learning Rate to prevent erasing old weights)
training_args = TrainingArguments(
    output_dir="./temp_checkpoint",
    per_device_train_batch_size=2,
    gradient_accumulation_steps=4,
    learning_rate=3e-5,  # Lower learning rate for continuous updates
    num_train_epochs=1,  # Keep epochs low per cycle to prevent over-indexing on the new batch
    bf16=True,
    logging_steps=5
)

trainer = SFTTrainer(
    model=model,
    train_dataset=combined_dataset,
    dataset_text_field="text",
    max_seq_length=512,
    args=training_args,
)

# 4. Update the weights and overwrite the saved adapter
trainer.train()
model.save_pretrained(adapter_path)

### Step-by-Step Architecture for On-The-Fly Random Transformation

# 1. Define Your Custom Transformation Logic

import random
def random_pii_transform(text):
    """
    Simulates a randomized Casper-style data transformation.
    In real usage, replace this with regex or a list of known entities.
    """
    transformations = [
        lambda t: t.replace("John Doe", "[REDACTED_NAME]"),
        lambda t: t.replace("John Doe", "Alex Smith"),  # Synthetic Swap
        lambda t: f"Please review this prompt: {t}",  # Context mutation
        lambda t: t  # Identity mapping (leave raw)
    ]

    # Pick a random transformation strategy
    chosen_transform = random.choice(transformations)
    return chosen_transform(text)


import torch
from transformers import AutoTokenizer

# 2. The Custom Data Collator (The Core Engine)

class CasperDynamicCollator:
    def __init__(self, tokenizer, max_length=512):
        self.tokenizer = tokenizer
        self.max_length = max_length

    def __call__(self, features):
        transformed_texts = []

        for item in features:
            # Extract raw string from your dataset structure
            raw_text = item["text"]

            # 1. Apply the randomized transformation on-the-fly
            mutated_text = random_pii_transform(raw_text)
            transformed_texts.append(mutated_text)

        # 2. Tokenize the freshly transformed batch
        batch = self.tokenizer(
            transformed_texts,
            padding=True,
            truncation=True,
            max_length=self.max_length,
            return_tensors="pt"
        )

        # 3. For Causal LM training, labels are usually a copy of the input_ids
        batch["labels"] = batch["input_ids"].clone()
        return batch


# 3. Execute the Continuous Training Script

from datasets import load_dataset
from transformers import AutoModelForCausalLM, TrainingArguments, Trainer
from peft import LoraConfig, get_peft_model

model_id = "HuggingFaceTB/SmolLM2-135M-Instruct"
tokenizer = AutoTokenizer.from_pretrained(model_id)
tokenizer.pad_token = tokenizer.eos_token

# Load Base Model and apply LoRA
model = AutoModelForCausalLM.from_pretrained(model_id, device_map="auto", torch_dtype=torch.bfloat16)
peft_config = LoraConfig(
    r=16, lora_alpha=32, target_modules=["q_proj", "v_proj"], task_type="CAUSAL_LM"
)
model = get_peft_model(model, peft_config)

# Load your raw dataset
dataset = load_dataset("json", data_files="raw_pii_stream.json", split="train")

# Instantiate your custom collator
data_collator = CasperDynamicCollator(tokenizer=tokenizer)

training_args = TrainingArguments(
    output_dir="./casper_output",
    per_device_train_batch_size=4,
    learning_rate=5e-5,
    num_train_epochs=3, # Multiple epochs are safe because transformations change every time
    bf16=True,
    remove_unused_columns=False # Crucial: prevents Hugging Face from dropping raw text fields
)

trainer = Trainer(
    model=model,
    args=training_args,
    train_dataset=dataset,
    data_collator=data_collator, # Injects the random on-the-fly changes
)

trainer.train()

"""
ultimately:

Overfitting Prevention: Because the transformations are calculated randomly at
runtime, if you train the model for 3 epochs, it will see 3 entirely different variations of
the same underlying data point.

Zero Storage Footprint: You do not need to save millions of permutations of your 
dataset to your disk; everything scales dynamically in system memory.

Deterministic Evaluation: You can keep a static "Golden evaluation set" unchanged,
while letting your training set continuously warp randomly to build strict boundary
definitions around what is or isn't PII.

links:
https://machinelearningmastery.com/a-gentle-introduction-to-transformers-library/
https://builtin.com/artificial-intelligence/pytorch-transformer-encoder 
https://www.code-brew.com/how-to-build-an-open-source-ai-model-like-llama/
https://python.plainenglish.io/transformers-for-natural-language-processing-7df2e97d1b9e
https://medium.com/@anas.aberchih1/supervised-fine-tuning-dilemma-whats-up-with-all-those-configurations-a1f9040bb74e
https://www.elastic.co/security-labs/getting-the-most-out-of-transforms-in-elastic
https://www.mdpi.com/2504-446X/9/11/757 # super important for training
https://clearintelligence.substack.com/p/fine-tuning-llama-llm-with-lora-a
https://arxiv.org/html/2604.15369v1
https://www.mdpi.com/2504-446X/9/11/757
https://labelyourdata.com/articles/machine-learning/data-versioning
https://apxml.com/courses/introduction-to-mlops/chapter-4-automation-and-cicd-for-ml/continuous-training
https://arxiv.org/html/2302.07944v3
"""


