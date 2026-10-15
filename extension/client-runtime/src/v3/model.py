"""Native intact pretrained BERT plus deterministic zero affine task heads."""
from __future__ import annotations
import hashlib
import json
from pathlib import Path
import torch
from torch import nn
from transformers import BertConfig, BertModel, BertTokenizerFast
from transformers.modeling_utils import no_init_weights
from safetensors.torch import load_file, save_file
from privoke_model.v3_contract import LABELS, TIERS, digest, validate_manifest
from ..classification import (Category, ClassificationResult, Sensitivity, Visibility, initialise_unpacked)
from ..detection.preprocessing import normalize_with_offsets


def tensor_hash(tensor):
    return hashlib.sha256(tensor.detach().cpu().contiguous().numpy().tobytes()).hexdigest()

def inventory(state):
    result = {}
    for name, value in state.items():
        if value.dtype != torch.float32 or not torch.isfinite(value).all():
            raise ValueError("Checkpoint requires complete finite float32 tensors.")
        result[name] = {"shape": list(value.shape), "dtype": "F32", "sha256": tensor_hash(value)}
    return result

def native_encoder(config, state):
    # Construction on meta cannot materialize random tensors. Strict assign loads
    # every learned tensor; nonpersistent indexing buffers are installed explicitly.
    with torch.device("meta"), no_init_weights():
        encoder = BertModel(BertConfig(**config), add_pooling_layer=True)
    encoder.load_state_dict(state, strict=True, assign=True)
    encoder.embeddings.position_ids = torch.arange(config["max_position_embeddings"]).expand((1, -1))
    encoder.embeddings.token_type_ids = torch.zeros((1, config["max_position_embeddings"]), dtype=torch.long)
    if any(p.is_meta for p in encoder.parameters()):
        raise ValueError("Pretrained loading left unmaterialized learned tensors.")
    return encoder

class PretrainedV3(nn.Module):
    def __init__(self, config, encoder_state, vocab, *, device="cpu", heads=None):
        super().__init__()
        self.encoder = native_encoder(config, encoder_state)
        hidden = config["hidden_size"]
        self.heads = nn.ParameterDict()
        for task, labels in LABELS.items():
            for part, shape in (("weight", (len(labels), hidden)), ("bias", (len(labels),))):
                name = task + "_" + part
                value = torch.zeros(shape, dtype=torch.float32) if heads is None else heads[name]
                if tuple(value.shape) != shape:
                    raise ValueError("Task head shape mismatch.")
                self.heads[name] = nn.Parameter(value.detach().clone())
        self.tokenizer = BertTokenizerFast(vocab_file=str(vocab), do_lower_case=True,
                                           model_max_length=512)
        self.device_name = device
        self.to(device)
        self.eval()  # Dropout off, autograd independently enabled by training.

    @classmethod
    def load(cls, manifest, checkpoint, config_file, vocab, *, device="cpu"):
        validate_manifest(manifest)
        for path, key in ((checkpoint, "blob"), (config_file, "config"), (vocab, "vocab")):
            if digest(Path(path).read_bytes()) != manifest[key]:
                raise ValueError("Runtime asset bytes do not match admitted manifest.")
        state = load_file(str(checkpoint), device="cpu")
        if inventory(state) != manifest["tensors"]:
            raise ValueError("Checkpoint inventory/hash mismatch.")
        encoder = {k.removeprefix("encoder."): v for k, v in state.items() if k.startswith("encoder.")}
        heads = {k.removeprefix("heads."): v for k, v in state.items() if k.startswith("heads.")}
        model = cls(json.loads(Path(config_file).read_text()), encoder, vocab, heads=heads, device=device)
        if set(model.state_dict()) != set(state):
            raise ValueError("Checkpoint includes unsupported or missing model keys.")
        return model

    def tokenize(self, texts):
        normalized = [normalize_with_offsets(text).text for text in texts]
        tokens = self.tokenizer(normalized, padding=True, truncation=False, return_tensors="pt")
        lengths = tokens["attention_mask"].sum(dim=1)
        if bool((lengths > 512).any()):
            raise ValueError("V3 input exceeds 512 native WordPiece tokens including special tokens.")
        return {k: v.to(self.device_name) for k, v in tokens.items()}

    def forward(self, texts):
        pooled = self.encoder(**self.tokenize(texts)).pooler_output
        return {task: pooled @ self.heads[task + "_weight"].T + self.heads[task + "_bias"] for task in LABELS}

    def predictions(self, texts):
        with torch.no_grad():
            logits = self(texts)
            sensitivity = logits["sensitivity"].softmax(-1).cpu()
            visibility = logits["visibility"].softmax(-1).cpu()
            categories = logits["category"].sigmoid().cpu()
        result = []
        for s, v, c in zip(sensitivity, visibility, categories):
            classification = initialise_unpacked(Sensitivity[LABELS["sensitivity"][int(s.argmax())]],
                Visibility[LABELS["visibility"][int(v.argmax())]],
                [Category[name] for name, probability in zip(LABELS["category"], c) if probability >= .5])
            confidence = round(min(max(float(torch.cat((s, c)).max()), 0.0), .999), 3)
            result.append((classification, confidence))
        return result

    def findings(self, text, identity):
        classification, confidence = self.predictions([text])[0]
        if classification.sensitivity() == Sensitivity.S0 and not classification.categories() and classification.visibility() == Visibility.PU:
            return []
        return [ClassificationResult(classification=classification, section_of_text=text,
            span=(0, len(text)) if text else None, confidence=confidence,
            reasoning="Experimental pretrained v3 contextual classification.", metadata=identity)]

    def export(self, path):
        state = {k: v.detach().cpu().contiguous() for k, v in self.state_dict().items()}
        save_file(state, str(path))
        return inventory(state)
