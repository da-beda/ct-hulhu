# Monitor startup baseline evidence

Continuous monitoring normally persists a current tree position for every newly selected log and then immediately polls for deltas. A downstream evidence pipeline may need to roll back an advanced checkpoint when post-processing fails, while still retaining the safe initial position established before the first delta poll.

Use:

```bash
ct-hulhu \
  -m \
  -resume \
  -d example.com \
  -json \
  -state-dir state/example.com \
  -monitor-baseline-output evidence/monitor-baseline.json
```

`-monitor-baseline-output` is valid only with `-m -resume`. It must be outside `-state-dir` and distinct from normal, malformed-entry, and log-list output paths.

## Ordering guarantee

The artifact is written after all selected logs have successfully initialized, but before the first delta poll can run:

```text
load existing state / verify saved consistency anchor
        |
        +--> fetch and validate current tree head
        |
        +--> persist state only for logs with no prior state
        |
        +--> require complete selected-log startup coverage
        |
        +--> write + fsync monitor startup baseline
        |
        v
first delta poll
```

If startup coverage is incomplete, ct-hulhu exits non-zero and does not produce the baseline artifact.

## Artifact semantics

The JSON document records:

- schema and artifact kind;
- creation time;
- absolute state directory;
- selection hash used by monitor state v3;
- only the monitor-state files newly initialized by this process;
- each file's relative name, size, SHA-256, and base64-encoded exact bytes.

Existing state files are intentionally omitted: a supervising transaction already had them before the process started. An empty `files` array is valid when every selected log already had matching state.

The artifact and its parent directory are restricted to `0600` and `0700`. State inputs must be private regular `monitor-*.json` files directly under the selected state directory. The output is created atomically, fsynced before publication, and never overwrites an existing destination.

## Intended downstream use

A supervising evidence pipeline can snapshot pre-run state, execute ct-hulhu, and then:

- commit the final state only after all downstream processing succeeds; or
- on failure, restore the pre-run state plus the baseline's newly initialized files.

That second rule preserves replayability on the first monitor run. It avoids restoring total state absence after a delta was already emitted but downstream promotion failed.

The baseline is not a replacement for raw output, malformed-entry evidence, exact log-list evidence, or the final state snapshot. It is a narrow pre-poll recovery artifact.
