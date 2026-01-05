#!/usr/bin/python3
#
# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.
"""
Fuzzer for airflow.serialization.serde module.

This targets the core serialization/deserialization used by the API Server
and Scheduler. The security boundary is the allowlist mechanism that controls
which classes can be deserialized.

Target: airflow.serialization.serde.deserialize()
Security boundary: allowed_deserialization_classes config
"""

import os
import sys

import atheris

os.environ.setdefault("AIRFLOW_HOME", "/tmp/airflow")

# Common class names that might appear in serialized data
_CLASSNAMES = [
    "builtins.dict",
    "builtins.list",
    "builtins.tuple",
    "builtins.set",
    "builtins.frozenset",
    "builtins.int",
    "builtins.str",
    "builtins.float",
    "builtins.bool",
    "datetime.datetime",
    "datetime.date",
    "datetime.timedelta",
    "pendulum.datetime.DateTime",
    "airflow.models.dag.DAG",
    "airflow.models.connection.Connection",
    # Potentially dangerous - should be blocked
    "os.system",
    "subprocess.Popen",
    "builtins.eval",
    "builtins.exec",
]

with atheris.instrument_imports(include=["airflow"], enable_loader_override=False):
    from airflow.serialization.serde import (
        CLASSNAME,
        DATA,
        VERSION,
        deserialize,
        serialize,
    )


def _fuzz_value(fdp: atheris.FuzzedDataProvider, depth: int = 0):
    """Generate a fuzzed value for serialization testing."""
    if depth > 3:
        return None
    choice = fdp.ConsumeIntInRange(0, 7)
    if choice == 0:
        return None
    if choice == 1:
        return fdp.ConsumeBool()
    if choice == 2:
        return fdp.ConsumeIntInRange(-2**31, 2**31)
    if choice == 3:
        return fdp.ConsumeString(256)
    if choice == 4:
        return fdp.ConsumeFloat()
    if choice == 5:
        return [_fuzz_value(fdp, depth + 1) for _ in range(fdp.ConsumeIntInRange(0, 4))]
    if choice == 6:
        return {
            fdp.ConsumeString(16): _fuzz_value(fdp, depth + 1)
            for _ in range(fdp.ConsumeIntInRange(0, 4))
        }
    # Return a serialized object structure
    return {
        CLASSNAME: fdp.PickValueInList(_CLASSNAMES),
        VERSION: fdp.ConsumeIntInRange(0, 10),
        DATA: _fuzz_value(fdp, depth + 1),
    }


def _build_payload(fdp: atheris.FuzzedDataProvider) -> dict:
    """Build a serialized payload structure."""
    classname = fdp.PickValueInList(_CLASSNAMES)

    # Sometimes use a completely fuzzed classname
    if fdp.ConsumeBool():
        classname = fdp.ConsumeString(128)

    version = fdp.ConsumeIntInRange(-1, 100)
    data = _fuzz_value(fdp)

    return {
        CLASSNAME: classname,
        VERSION: version,
        DATA: data,
    }


def TestInput(input_bytes: bytes):
    if len(input_bytes) > 4096:
        return

    fdp = atheris.FuzzedDataProvider(input_bytes)

    # Test 1: Deserialize a fuzzed payload
    try:
        payload = _build_payload(fdp)
        _ = deserialize(payload)
    except (ImportError, TypeError, ValueError, KeyError, AttributeError, RecursionError, OverflowError):
        # Expected - allowlist blocks dangerous classes, or malformed data
        pass

    # Test 2: Serialize then deserialize round-trip
    try:
        obj = _fuzz_value(fdp)
        if obj is not None:
            serialized = serialize(obj)
            if serialized is not None:
                _ = deserialize(serialized)
    except (TypeError, ValueError, RecursionError, AttributeError, OverflowError):
        pass

    # Test 3: Test with type hints
    try:
        payload = _build_payload(fdp)
        type_hint = fdp.PickValueInList([None, dict, list, str, int])
        _ = deserialize(payload, type_hint=type_hint)
    except (ImportError, TypeError, ValueError, KeyError, AttributeError, RecursionError, OverflowError):
        pass


def main():
    atheris.Setup(sys.argv, TestInput, enable_python_coverage=True)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
