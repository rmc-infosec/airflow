# Airflow OSS-Fuzz fuzzers

This directory contains the upstream-owned fuzz targets used by OSS-Fuzz for
Apache Airflow.

## Security Model Alignment

These fuzzers target code paths with **clear security boundaries** per
Airflow's [security model](../airflow-core/docs/security/security_model.rst):

- **Serialization/Deserialization**: Used by API Server and Scheduler with
  allowlist-based security. Input comes from authenticated API users.
- **Connection URI Parsing**: Used when creating/updating connections via API.

We explicitly **avoid** fuzzing code paths in the "DAG author trust zone"
where Airflow's policy is that DAG authors can execute arbitrary code.

## What's here

- `*_fuzz.py`: Atheris fuzz targets (packaged by OSS-Fuzz via `pyinstaller`).
- `*.dict`: Optional libFuzzer dictionaries for structured inputs.
- `*.options`: libFuzzer options (e.g. `max_len`) tuned per target.
- `seed_corpus/<fuzzer>/...`: Small seed corpora that get zipped and uploaded to
  OSS-Fuzz for each target.

## Fuzzers

| Fuzzer | Target | Security Boundary |
|--------|--------|-------------------|
| `serde_fuzz.py` | `airflow.serialization.serde.deserialize()` | Allowlist check |
| `serialized_dag_fuzz.py` | `SerializedDAG.from_dict()` | Schema validation |
| `connection_uri_fuzz.py` | `Connection._parse_from_uri()` | API input validation |

## Supported engines / sanitizers (Python constraints)

Airflow is fuzzed as a **Python** OSS-Fuzz project. Practically, this means:

- **Fuzzing engine**: `libfuzzer` (Atheris). Other engines (AFL/honggfuzz) are
  not typically used/supported for Python targets in OSS-Fuzz.
- **Sanitizers**: `address`, `undefined`, `coverage`, `introspector` are the
  relevant modes. **MSan (`memory`) is not supported** for Python OSS-Fuzz
  projects.

## Running locally with OSS-Fuzz helper

From a checkout of `google/oss-fuzz`:

```bash
# Build + basic validation:
python3 infra/helper.py build_fuzzers --clean --sanitizer address airflow /path/to/airflow
python3 infra/helper.py check_build --sanitizer address airflow

# Coverage build + validation:
python3 infra/helper.py build_fuzzers --clean --sanitizer coverage airflow /path/to/airflow
python3 infra/helper.py check_build --sanitizer coverage airflow
```

## Running locally without OSS-Fuzz

```bash
# Install atheris
pip install atheris

# Run a fuzzer (quick test, 60 seconds)
cd ossfuzz
python serde_fuzz.py -max_total_time=60

# Run with corpus
mkdir -p corpus/serde_fuzz
python serde_fuzz.py corpus/serde_fuzz -max_total_time=300
```
