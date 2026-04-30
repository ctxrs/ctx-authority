# Schema references

The canonical schema descriptions live in:

- [../product-specs/run-profiles.md](../product-specs/run-profiles.md)
- [../product-specs/policy-schema.md](../product-specs/policy-schema.md)
- [../product-specs/receipt-schema.md](../product-specs/receipt-schema.md)

## Config profile shape

```yaml
profiles:
  - id: string
    agent: string?
    env:
      ENV_NAME: non-secret string
    http_resources:
      - id: string
        scheme: http | https # optional; defaults to https
        host: host-or-host-port
        secret_ref: backend-scoped-reference
        auth:
          type: bearer
        allow:
          methods: [HTTP_METHOD]
          path_prefixes: [/absolute/non-root/prefix]
```

This file intentionally points to the canonical product specs instead of
duplicating schema definitions.
