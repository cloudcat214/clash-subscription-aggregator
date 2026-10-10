from __future__ import annotations

import sys

from aggregator.validators import _run, _version


def _invalid_utf8_command() -> list[str]:
    return [
        sys.executable,
        "-c",
        "import sys; sys.stdout.buffer.write(bytes([255]))",
    ]


def test_core_output_with_non_utf8_bytes_is_redacted_without_decode_failure() -> None:
    command = _invalid_utf8_command()

    assert _run(command, timeout=5) == {"status": "passed", "exit_code": 0}
    assert _version(command, timeout=5) == "�"
