from __future__ import annotations

import re
import subprocess
import tempfile
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from .outputs import render_clash_config
from .quality import node_key

_UUID_RE = re.compile(
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
)
_SECRET_RE = re.compile(
    r"\b(uuid|password|passwd|psk|secret|token|auth-str|private-key|key)\b"
    r"\s*[=:]?\s*\S+",
    re.IGNORECASE,
)
_SECRET_FIELD_RE = re.compile(
    r"(uuid|password|passwd|psk|secret|token|auth|private-key|key)", re.IGNORECASE
)
_MAX_DETAIL = 300
_MAX_NODE_ERROR = 400


class CoreValidationError(RuntimeError):
    """Raised when a configured client rejects generated configuration.

    ``category`` stays inside the probe error vocabulary so a rejected node can
    be recorded without inventing a parallel status taxonomy.
    """

    def __init__(
        self, message: str, *, category: str = "core_validation_error"
    ) -> None:
        super().__init__(message)
        self.category = category


def _node_secrets(node: Mapping[str, object]) -> list[str]:
    """Collect this node's credential values so they can be redacted by value.

    Walks nested option mappings (e.g. ``ws-opts.headers.authorization``) so a
    token that appears in client output without a field label is still removed.
    """
    values: set[str] = set()

    def collect(value: object, level: int, field_name: str | None = None) -> None:
        if level > 4:
            return
        if isinstance(value, str):
            if field_name and _SECRET_FIELD_RE.search(field_name) and value:
                values.add(value)
        elif isinstance(value, Mapping):
            for nested_field, field_value in value.items():
                collect(field_value, level + 1, str(nested_field))
        elif isinstance(value, (list, tuple)):
            for item in value:
                collect(item, level + 1, field_name)

    collect(node, 0)
    return sorted(values, key=len, reverse=True)


def _sanitize_output(
    text: object, limit: int = _MAX_DETAIL, secrets: Sequence[str] = ()
) -> str:
    """Return a bounded, credential-free excerpt of client output."""
    if not isinstance(text, str):
        return ""
    cleaned = text
    for secret_value in secrets:
        cleaned = cleaned.replace(secret_value, "<redacted>")
    cleaned = _UUID_RE.sub("<redacted>", cleaned)
    cleaned = _SECRET_RE.sub(lambda match: f"{match.group(1)}=<redacted>", cleaned)
    return " ".join(cleaned.split())[:limit]


def _failure_detail(result: object, secrets: Sequence[str] = ()) -> str:
    stderr = _sanitize_output(getattr(result, "stderr", ""), secrets=secrets)
    if stderr:
        return stderr
    return _sanitize_output(getattr(result, "stdout", ""), secrets=secrets)


def _run(
    command: list[str], timeout: float, secrets: Sequence[str] = ()
) -> dict[str, object]:
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise CoreValidationError(
            "timeout: client did not finish", category="timeout"
        ) from exc
    except OSError as exc:
        raise CoreValidationError(
            "client_start_failed", category="process_start_error"
        ) from exc
    if result.returncode != 0:
        detail = _failure_detail(result, secrets)
        message = f"client_rejected_config exit={result.returncode}"
        raise CoreValidationError(
            f"{message}: {detail}" if detail else message,
            category="core_validation_error",
        )
    return {"status": "passed", "exit_code": 0}


def _version(command: list[str], timeout: float) -> str:
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise CoreValidationError(
            "timeout: client did not finish", category="timeout"
        ) from exc
    except OSError as exc:
        raise CoreValidationError(
            "client_start_failed", category="process_start_error"
        ) from exc
    if result.returncode != 0:
        raise CoreValidationError(
            "client_version_failed", category="process_start_error"
        )
    first_line = next(
        (line for line in (result.stdout or "").splitlines() if line.strip()), None
    )
    if first_line is None:
        first_line = next(
            (line for line in (result.stderr or "").splitlines() if line.strip()), None
        )
    if first_line is None:
        raise CoreValidationError(
            "client_version_empty", category="process_start_error"
        )
    return first_line[:200]


def validate_node_configs(
    proxies: Sequence[Mapping[str, object]],
    *,
    mihomo_path: str,
    timeout: float = 30.0,
) -> list[dict[str, object]]:
    """Validate every candidate in its own Mihomo run; never raises per node.

    A single bad node must not take down the whole batch: each candidate gets
    an independent result and only the failing node is excluded. Rows carry the
    probe contract fields (``node_key``/``error_category``/rounds) so the
    failed-pool merge can reuse its existing entry shape, and every detail is
    bounded and redacted by the node's own credential values.
    """
    rows: list[dict[str, object]] = []
    for proxy in proxies:
        row: dict[str, object] = {
            "node_key": "",
            "protocol": "unknown",
            "status": "failed",
            "error_category": "core_validation_error",
            "detail": "",
            "rounds_passed": 0,
            "rounds_total": 1,
        }
        try:
            node = dict(proxy)
            secrets = _node_secrets(node)
            row["node_key"] = node_key(node)
            row["protocol"] = str(node.get("type") or "unknown")
            try:
                with tempfile.TemporaryDirectory(
                    prefix="aggregator-node-check-"
                ) as temp:
                    root = Path(temp)
                    config_path = root / "config.yaml"
                    config_path.write_text(
                        render_clash_config([node]), encoding="utf-8"
                    )
                    _run(
                        [mihomo_path, "-t", "-f", str(config_path), "-d", str(root)],
                        timeout,
                        secrets=secrets,
                    )
                row["status"] = "passed"
                row["error_category"] = None
                row["rounds_passed"] = 1
            except CoreValidationError as exc:
                row["error_category"] = str(
                    getattr(exc, "category", "core_validation_error")
                )
                row["detail"] = (
                    _sanitize_output(str(exc), _MAX_NODE_ERROR, secrets)
                    or "core_validation_error"
                )
            except (OSError, TypeError, ValueError) as exc:
                row["detail"] = f"node_check_failed: {type(exc).__name__}"
        except Exception as exc:  # noqa: BLE001 - one bad node must not stop the batch
            row["detail"] = f"node_check_failed: {type(exc).__name__}"
        rows.append(row)
    return rows


def validate_generated_artifacts(
    root: Path,
    *,
    mihomo_path: str | None = None,
    sing_box_path: str | None = None,
    timeout: float = 30.0,
    require: bool = False,
) -> dict[str, Any]:
    """Run real client syntax checks without logging their raw output."""
    result: dict[str, Any] = {"status": "not_tested", "clients": {}}
    clash_config = root / "clash" / "config.yaml"
    sing_box_config = root / "sing-box" / "config.json"
    selected_mihomo = mihomo_path
    selected_sing_box = sing_box_path
    if selected_mihomo:
        mihomo_version = _version([selected_mihomo, "-v"], timeout)
        result["clients"]["mihomo"] = _run(
            [selected_mihomo, "-t", "-f", str(clash_config), "-d", str(root / "clash")],
            timeout,
        )
        result["clients"]["mihomo"]["version"] = mihomo_version
    elif require:
        raise CoreValidationError("mihomo_path_missing")
    else:
        result["clients"]["mihomo"] = {"status": "not_available"}
    if selected_sing_box:
        sing_box_version = _version([selected_sing_box, "version"], timeout)
        result["clients"]["sing-box"] = _run(
            [selected_sing_box, "check", "-c", str(sing_box_config)], timeout
        )
        result["clients"]["sing-box"]["version"] = sing_box_version
    elif require and selected_mihomo is None:
        raise CoreValidationError("sing_box_path_missing")
    else:
        result["clients"]["sing-box"] = {"status": "not_available"}
    statuses = [item["status"] for item in result["clients"].values()]
    result["status"] = (
        "passed"
        if "passed" in statuses
        and all(status != "not_available" for status in statuses)
        else "not_tested"
    )
    return result
