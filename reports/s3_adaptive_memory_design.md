# S3 adaptive-memory design

## Scope

The adaptive threat memory can now use either the existing local pickle file or
an S3 object. The frozen training-only threat memory remains a separate local
artifact and is never written to S3 by this adapter.

No AWS resources, credentials, buckets, or deployments were created. The S3
client was exercised only through mocked unit tests.

## Storage abstraction

`PersistentAdaptiveMemory` still owns document validation, embedding, vector
index construction, serialization, and retrieval. It now writes serialized
bytes through an `AdaptiveMemoryStorage` protocol.

- `LocalFileStorage` preserves the existing development and regular-Docker
  behavior.
- `S3AdaptiveMemoryStorage` reads and writes the same serialized payload from
  S3.

The application selects the backend in `src/api/main.py`:

```text
ADAPTIVE_MEMORY_STORAGE=local|s3
```

The default is `local`.

In S3 mode, the application lazily imports `boto3` and creates an S3 client.
The Lambda Python base image supplies the AWS SDK; local unit tests inject a
mock client and do not require AWS credentials.

S3 mode requires:

```text
ADAPTIVE_MEMORY_S3_BUCKET=<bucket name>
ADAPTIVE_MEMORY_S3_KEY=adaptive/adaptive_threat_memory.pkl
```

The object is initialized as an empty memory only when explicitly enabled:

```text
ADAPTIVE_MEMORY_S3_ALLOW_INITIALIZE=true
```

The default is `false`. A missing object otherwise fails initialization
clearly instead of silently using an empty memory. AWS credentials and client
configuration are supplied by the runtime; this change does not configure
credentials.

## Object format

The S3 object body is the existing pickle representation:

```python
{
    "documents": list[ThreatMemoryDocument],
    "embeddings": list[numpy.ndarray],
}
```

Document IDs, channel, label, text, sender, and receiver are retained through
the existing `ThreatMemoryDocument` dataclass. Embeddings remain normalized and
are checked by the existing `InMemoryVectorStore`, including dimension
compatibility.

No API keys or other secrets are added to the object.

## Feedback behavior

Existing eligibility rules are unchanged. Only feedback with a corrected label
and an eligible feedback type is passed to `add_document`. Rejected or
ineligible feedback does not call storage and therefore does not write an S3
object.

The frozen training memory and S3 adaptive memory are combined by the existing
`CombinedThreatMemoryStore`, so detection continues to retrieve from both.
`/health` continues to report the adaptive-memory document count without a
response-schema change.

## Concurrency strategy

Each S3 load records the object's ETag as a version token. Writes use:

- `If-None-Match: *` when initializing a missing object.
- `If-Match: <loaded ETag>` when updating an existing object.

If another invocation writes the object first, S3 rejects the stale
conditional write and the adapter raises `AdaptiveMemoryConcurrencyError`.
The in-memory document is committed only after the S3 write succeeds, so a
failed write is not reported as accepted and does not silently lose the
feedback.

This provides optimistic lost-update protection for the single-object
read-modify-write format. It does not merge concurrent updates or retry them,
and it does not provide a global transaction across other application data.
The caller must surface the conflict and retry after reloading if desired.

## Failure behavior

- Missing S3 objects fail startup by default.
- S3 permission, network, malformed-response, and serialization failures are
  raised explicitly.
- Conditional-write conflicts are raised explicitly.
- The existing API maps persistence failures to its existing HTTP 500 error
  response; public request and response schemas were not changed.

## Tests

Focused mocked-client tests cover:

1. Valid memory loading and metadata preservation.
2. Explicit empty-memory initialization policy.
3. Accepted phishing feedback persistence.
4. Accepted legitimate feedback persistence.
5. Ineligible feedback with no write.
6. Permission/network-style persistence failure.
7. Conditional concurrent-update conflict handling.
8. `/health` document-count reporting after an update.

Real S3 behavior, IAM permissions, bucket versioning, Lambda execution
environments, and AWS network behavior remain untested.

The focused validation run completed with 33 passing tests across the S3
adapter, existing adaptive-memory, knowledge-updater, feedback, and API
client test modules. A subsequent storage-focused rerun completed with 15
passing tests.
