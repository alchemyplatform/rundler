# Keep JSON Config Loading Local and S3 Capable

## Rule

Preserve both local path and `s3://bucket/key` JSON config loading.

## Why

`get_json_config` reads local paths or S3 using AWS defaults. Mempool and
builder configs can depend on this behavior.

## Examples

- Good: preserve identical schemas for local and S3 JSON config.
- Bad: add a config mode that only works locally when deployments need S3.

## Exceptions

Developer-only debug commands may use local files.
