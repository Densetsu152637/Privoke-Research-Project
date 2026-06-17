# Shared Contracts

This directory contains resources that must be accessible to more than one service. At present, the most important shared asset is the protobuf contract under `proto/privoke/v1`.

## Purpose

Shared files should define stable interfaces, not service-specific implementation details. Use this directory for:

- protobuf definitions,
- shared schema documentation,
- small cross-service fixtures,
- versioned interface notes.

Do not place detector-specific rules, prompts, model weights, or service-local configuration here unless more than one service depends on them.

## Current Contract

`proto/privoke/v1/parameters.proto` defines parameter snapshot and update messages used by:

- `model-streaming-service`,
- `param-update-service`,
- `privoke-fuzzer`,
- `client-runtime` parameter fetch commands.

## Expected Workflow

When changing a shared API:

1. Update the protobuf schema.
2. Regenerate language-specific bindings in the affected services.
3. Update each service README if the contract changes behavior.
4. Add compatibility notes if an older service version cannot read the new message.

## Subagent Tasks

Subagents assigned here should focus on contract stability:

- add versioned protobuf fields instead of breaking existing fields,
- document producer and consumer expectations,
- avoid raw prompt text in telemetry or update contracts unless explicitly approved,
- keep service boundaries clear.
