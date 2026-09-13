# Security model

Valsec bounds file and archive size/count, rejects traversal and unsafe archive members, validates text uploads, and never extracts ZIP members to disk. Config, training, result, and report endpoints enforce owner scope when authentication is enabled. Learned mappings are unique and isolated by user and vendor.

Ollama endpoints must resolve to an allowed local host. Model output is bounded, parsed as structured JSON, type-checked against the schema field catalogue, and kept untrusted until operator approval. Remediation output is restricted to complete vendor command blocks and rejects destructive or diagnostic commands. AI does not participate in compliance verdict, severity, or score computation.

Do not place secrets in configuration files uploaded for a demo. Use `.env` only for deployment credentials and never commit it.
