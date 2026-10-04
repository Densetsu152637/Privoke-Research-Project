FROM python:3.11-slim-bookworm
WORKDIR /workspace
COPY evaluation/requirements.txt /tmp/evaluation-requirements.txt
COPY evaluation/requirements-training.txt /tmp/evaluation-training-requirements.txt
COPY extension/runtime-supervisor/requirements.txt /tmp/supervisor-requirements.txt
RUN pip install --no-cache-dir -r /tmp/evaluation-requirements.txt \
    -r /tmp/supervisor-requirements.txt \
    -r /tmp/evaluation-training-requirements.txt
COPY shared /workspace/shared
COPY models/generate_baseline.py /workspace/models/generate_baseline.py
COPY evaluation /workspace/evaluation
RUN mkdir -p /workspace/extension/client-runtime/src/detection \
    /workspace/extension/client-runtime/src/LLM/privoke
COPY extension/client-runtime/src/model.py /workspace/extension/client-runtime/src/model.py
COPY extension/client-runtime/src/transformer_encoder.py /workspace/extension/client-runtime/src/transformer_encoder.py
COPY extension/client-runtime/src/detection/preprocessing.py /workspace/extension/client-runtime/src/detection/preprocessing.py
COPY extension/client-runtime/src/env.py /workspace/extension/client-runtime/src/env.py
COPY extension/client-runtime/src/LLM/privoke/parameter_stream.py /workspace/extension/client-runtime/src/LLM/privoke/parameter_stream.py
COPY extension/client-runtime/src/LLM/privoke/scratch_presence_model.py /workspace/extension/client-runtime/src/LLM/privoke/scratch_presence_model.py
RUN mkdir -p /workspace/extension/client-runtime/generated \
    && python -m grpc_tools.protoc -I /workspace/shared/proto \
      --python_out=/workspace/extension/client-runtime/generated \
      --grpc_python_out=/workspace/extension/client-runtime/generated \
      /workspace/shared/proto/privoke/v1/runtime.proto \
      /workspace/shared/proto/privoke/v1/parameters.proto \
      /workspace/shared/proto/privoke/v1/telemetry.proto
ENV PYTHONPATH=/workspace/evaluation:/workspace/shared/python:/workspace/extension/client-runtime:/workspace/extension/client-runtime/generated:/workspace/models
ENV PRIVOKE_EVAL_IN_CONTAINER=true
ENV PRIVOKE_RUNTIME_TARGET=client-runtime:50054
ENV MODEL_ID=privoke-balanced
WORKDIR /workspace/evaluation
CMD ["python", "run-component-tests.py", "evaluator"]
