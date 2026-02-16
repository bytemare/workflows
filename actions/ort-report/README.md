# ORT report composite action

This action reads ORT evaluation results and produces:
- a human-friendly job summary
- lightweight GitHub annotations

## Inputs
- `artifact_dir` (default: `ort-artifacts`): directory containing ORT artifacts
- `ort_failed` (default: `false`): whether the ORT step failed

## Behavior
- Prefers `evaluation-result.json` (includes resolutions); falls back to `evaluated-model.json`.
- Attempts a small set of standard ORT result paths if artifacts are missing.
- Emits a single error annotation if ORT failed and no evaluation file is found.

## Security notes
- Does not execute shell commands or external tools.
- Sanitizes annotation output to avoid command injection.
