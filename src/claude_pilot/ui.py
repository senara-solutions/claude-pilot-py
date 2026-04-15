"""Stderr log renderer with ANSI colors. Port of src/ui.ts."""

from __future__ import annotations

from .logger import write_file_log, write_log
from .types import ResolvedGuardrailConfig

RESET = "\x1b[0m"
DIM = "\x1b[2m"
BOLD = "\x1b[1m"
GREEN = "\x1b[32m"
YELLOW = "\x1b[33m"
RED = "\x1b[31m"
CYAN = "\x1b[36m"
MAGENTA = "\x1b[35m"
ORANGE = "\x1b[38;5;208m"


def _log(msg: str) -> None:
    write_log(msg + "\n")


def log_init(session_id: str, model: str, task_id: str | None = None) -> None:
    task_str = f", task {task_id}" if task_id else ""
    _log(f"{DIM}[init]{RESET} Session {session_id[:8]}, model {model}{task_str}")


def log_tool(tool_name: str, detail: str, decision: str | None = None) -> None:
    if decision:
        color = GREEN if decision == "ALLOW" else RED if decision == "DENY" else YELLOW
        decision_str = f" → {color}{decision}{RESET}"
    else:
        decision_str = ""
    _log(f"{DIM}[tool]{RESET} {BOLD}{tool_name}{RESET}: {detail}{decision_str}")


def log_question(question: str, answer: str | None = None) -> None:
    answer_str = f' → {GREEN}"{answer}"{RESET}' if answer else ""
    _log(f'{MAGENTA}[question]{RESET} "{question}"{answer_str}')


def log_text(text: str) -> None:
    write_log(f"{DIM}{text}{RESET}")


def log_done(turns: int, cost_usd: float | None, duration_ms: int) -> None:
    secs = f"{duration_ms / 1000:.0f}"
    cost_str = f"${cost_usd:.2f}" if cost_usd is not None else "$?"
    _log(f"\n{GREEN}[done]{RESET} Success | {turns} turns | {cost_str} | {secs}s")


def log_error(subtype: str, errors: list[str]) -> None:
    _log(f"\n{RED}[error]{RESET} {subtype}: {', '.join(errors)}")


def log_denied(tool_name: str, detail: str) -> None:
    _log(f"{RED}[denied]{RESET} {tool_name}: {detail}")


def log_retry(reason: str) -> None:
    _log(f"{YELLOW}[retry]{RESET} {reason}")


def log_fallback(reason: str) -> None:
    _log(f"{YELLOW}[fallback]{RESET} {reason} — answering from claude-pilot")


def log_config(cwd: str, config_path: str, found: bool, relay: bool) -> None:
    status = "found" if found else "NOT FOUND"
    relay_str = "enabled" if relay else "disabled"
    _log(f"{DIM}[config]{RESET} cwd={cwd} config={config_path} [{status}] relay={relay_str}")


def log_tool_request(tool_name: str, detail: str) -> None:
    _log(f"{DIM}[tool:request]{RESET} {BOLD}{tool_name}{RESET}: {detail}")


def log_relay_send(tool_name: str) -> None:
    _log(f"{DIM}[relay:send]{RESET} {tool_name} → agent")


def log_relay_recv(tool_name: str, action: str, latency_ms: int) -> None:
    color = GREEN if action == "allow" else RED if action == "deny" else YELLOW
    _log(f"{DIM}[relay:recv]{RESET} {tool_name} ← {color}{action}{RESET} ({latency_ms}ms)")


def log_verbose(msg: str) -> None:
    _log(f"{DIM}[debug] {msg}{RESET}")


def log_escalate(tool_name: str, detail: str) -> None:
    _log(f"{CYAN}[ESCALATE]{RESET} Claude wants to use: {BOLD}{tool_name}{RESET}")
    _log(f"  {detail}")


def log_question_escalate(question: str) -> None:
    _log(f"{CYAN}[QUESTION]{RESET} {question}")


def log_prompt(prompt: str) -> None:
    write_file_log(f"[prompt] {prompt}\n")


def log_guardrail(type_: str, detail: str) -> None:
    _log(f"\n{ORANGE}[guardrail]{RESET} {BOLD}{type_}{RESET}: {detail}")


def log_env(env_path: str, loaded: bool, count: int) -> None:
    if loaded:
        _log(f"{DIM}[env]{RESET} path={env_path} [LOADED] vars={count}")
    else:
        _log(f"{DIM}[env]{RESET} path={env_path} [NOT FOUND]")


def log_guardrail_config(config: ResolvedGuardrailConfig) -> None:
    parts: list[str] = [f"maxTurns={config.maxTurns}"]
    if config.stallThreshold > 0:
        parts.append(f"stallThreshold={config.stallThreshold}")
    if config.emptyResponseThreshold > 0:
        parts.append(f"emptyResponseThreshold={config.emptyResponseThreshold}")
    if config.idleTimeoutMs > 0:
        parts.append(f"idleTimeout={config.idleTimeoutMs / 1000}s")
    if config.maxBudgetUsd > 0:
        parts.append(f"maxBudget=${config.maxBudgetUsd}")
    _log(f"{DIM}[guardrails]{RESET} {' '.join(parts)}")
