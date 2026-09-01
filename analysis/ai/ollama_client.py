"""Thin HTTP wrapper over the local Ollama chat API (DESIGN §14.7).

Ollama already *is* an HTTP server (default 127.0.0.1:11434, or the `ollama` compose
service via OLLAMA_URL) — so this is a thin client, not a wrapper service. stdlib only
(urllib), consistent with the GUI's RAG client: no new dependency for an HTTP POST.

The `chat` method is the single seam the orchestration loop (engine.py) depends on; a
test can substitute any object exposing the same `chat(messages, tools)` signature to
exercise the loop offline (see tests/test_ai.py).
"""
from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path

def _repo_root_on_path() -> None:
    """Put the repository root on sys.path once, so `tools/` is importable from this tree.

    Idempotent. The unconditional version of this grew sys.path by one entry per call, and
    `analysis/gui/app.py` builds a client per request."""
    root = str(Path(__file__).resolve().parents[2])
    if root not in sys.path:
        sys.path.insert(0, root)


# The guard must never be able to stop this module LOADING. The Docker image builds with context
# `./analysis` and copies that tree alone, so `tools/` is not present and `parents[2]` is `/` —
# a bare `from tools import hostmem` raised ModuleNotFoundError at import, `gui/app.py` imports
# this at module scope, and the container crash-looped under `restart: unless-stopped`. The
# defensive shape was already in this file (see `configured_model` below) and was not followed.
# Without hostmem there is simply no guard, which is the same fail-open every unmeasurable input
# already gets.
_repo_root_on_path()
try:
    from tools import hostmem  # noqa: E402 — shared with rag/, see tools/hostmem.py
except ImportError:  # pragma: no cover — exercised only in a deployment without tools/
    hostmem = None

DEFAULT_URL = "http://127.0.0.1:11434"
# The default model, decided 2026-08-29 on the measured corpus rather than on two ad-hoc queries.
# `qwen2.5:14b` was preferred from 2026-07-21 because it EMITTED tool calls where the 7B narrated
# them in prose, and grounding/scoring must actually run (§6). The toolbench corpus of 2026-07-24
# (docs/analysis/performance.md) then measured both and said the opposite: 7b-instruct passes 54/60
# cases against the 14b's 44/60, answers in a non-Latin script zero times against 7 of 60 — coherent,
# correctly grounded answers to English prompts, in Thai — and runs 2.2x faster. The 14b leads on one
# metric, narration, by one event out of 42. The evidence for preferring it was thin when it was
# published and it has not improved since, so the default is the model the corpus supports.
#
# The 14b remains SELECTABLE and is not a fallback: the operator chooses it in the Assistant's model
# picker (which persists the choice through `llm_model`), or with EVENTHOUND_LLM_MODEL. Whatever is
# chosen still has to fit the host — `memory_preflight` guards the load, and on a machine that
# cannot hold it the refusal explains itself rather than taking the session down (2026-08-28).
DEFAULT_MODEL = "qwen2.5:7b-instruct"
LARGE_MODEL = "qwen2.5:14b"
# What a load costs beyond the model's on-disk size (KV cache, context, runtime). Taken from the
# incident rather than guessed: Ollama predicted 9.1 GiB for the model it reports as 8.99 GB
# (8.37 GiB), a ratio of 1.09, rounded up for the margin.
LOAD_OVERHEAD = 1.15
# Availability probes (/api/tags, /api/ps) must not inherit the chat timeout. They run on the GUI's
# event loop inside `_ai_stream`, and at 180 s a thrashing-but-listening Ollama — precisely the
# state the guard exists for — froze the whole interface with no SSE headers flushed.
PROBE_TIMEOUT = 5


def default_model() -> str:
    """`DEFAULT_MODEL`, on every host.

    It used to branch on RAM — the 14b above 24 GiB, the 7B below — which answered the *hardware*
    question while leaving the *quality* one open, and a memory incident is not evidence about
    model quality. The corpus settled the quality question in the 7B's favour (see DEFAULT_MODEL),
    so there is nothing left for the branch to decide: a large host gets the better model too, and
    the operator who wants the 14b anyway selects it. Kept as a function, not collapsed into the
    constant, because it is the seam the installer and `uninstall.sh` ask through and every caller
    already goes past it."""
    return DEFAULT_MODEL


class OllamaError(RuntimeError):
    """Ollama unreachable or replied with an error — surfaced honestly, never hidden (§6)."""


def configured_model() -> str:
    """The model to talk to: the environment first, then the shared settings store, then the default.

    Public because the shell asks the same question: `setup.sh model` prints what will actually be
    pulled and `uninstall.sh --purge-models` removes what is actually installed, and both were
    asking `default_model()` — which does not know about a model the analyst selected in the GUI.

    `llm_model` is where the Assistant's model picker stores the analyst's choice, so a model
    selected in the GUI is also the model the CLI, the MCP tools and the next session talk to.

    It is read through `get_setting`, and that is the whole of the second fix this line has needed.
    The first (`70483b8`) connected a setting nothing had ever read and reached for
    `load().get("llm_model")` — the store keeps settings under `data["settings"]`, so the lookup
    returned None and the setting stayed as inert as before, with a commit message saying it was
    connected and a docstring describing a precedence chain the code did not have. Reading the
    store's own accessor instead of its raw dict is what makes that unrepeatable.

    The environment still wins, because that is what the compose service and a one-off run set."""
    env = os.environ.get("EVENTHOUND_LLM_MODEL")
    if env:
        return env
    try:
        _repo_root_on_path()
        from tools import eventhound_config
        stored = eventhound_config.get_setting("llm_model")
        if stored:
            return str(stored)
    except Exception:
        # A settings store that cannot be read must not stop the engine talking to Ollama.
        pass
    return default_model()


class OllamaClient:
    """Local Ollama chat client. Model and URL come from the environment by default
    (OLLAMA_URL / EVENTHOUND_LLM_MODEL), with the shared settings store (`llm_model`) as the
    fallback, matching the compose service wiring."""

    def __init__(self, url: str | None = None, model: str | None = None,
                 timeout: int = 180) -> None:
        self.url = (url or os.environ.get("OLLAMA_URL", DEFAULT_URL)).rstrip("/")
        self.model = model or configured_model()
        self.timeout = timeout
        self._model_bytes_cache: int | None | str = "unmeasured"

    # -- availability -------------------------------------------------------

    def _match(self, name: str) -> bool:
        """Does this /api/tags or /api/ps entry name the configured model?

        Ollama reports tags as "name:tag". An EXACT match is required: a base-name match
        ("qwen2.5" against "qwen2.5:14b") would report available and then 404 on chat, because chat
        sends the exact configured string. Only a name given WITHOUT a tag accepts any tag."""
        return name == self.model or (":" not in self.model
                                      and name.split(":", 1)[0] == self.model)

    def _models(self) -> list[dict] | None:
        """The locally pulled models as Ollama reports them, or None when it cannot be reached.

        None means "unknown", never "none pulled" — collapsing those two is how a transport failure
        turns into a confident wrong answer."""
        try:
            return self._get("/api/tags", timeout=PROBE_TIMEOUT).get("models") or []
        except OllamaError:
            return None

    def available(self, models: list[dict] | None = None) -> bool:
        """True if Ollama answers AND the configured model is pulled. Used by the CLI and the e2e
        test to degrade/skip cleanly instead of crashing when nothing is up.

        `models` lets a caller that already fetched /api/tags pass it in rather than provoking a
        second identical request — `unusable_reason` asks both this and the size question."""
        if models is None:
            models = self._models()
            if models is None:
                return False
        return any(self._match(m.get("name", "")) for m in models)

    def _model_bytes(self, models: list[dict] | None = None) -> int | None:
        """What the configured model weighs, as Ollama itself reports it in /api/tags.

        Measured, not tabulated per model name: a hardcoded size table would be wrong the day
        someone points EVENTHOUND_LLM_MODEL at anything we did not foresee, which is the whole
        reason the model is configurable.

        ONLY A SUCCESSFUL MEASUREMENT IS CACHED. The first version wrote `None` before issuing the
        request, so a client built while the model was still being pulled kept answering "size
        unknown" — which disables the guard — for the rest of its life, even after the pull
        finished. A failure must be retried, not remembered.

        When the configured name carries no tag, the LARGEST matching tag wins rather than the
        first one Ollama happens to list: `qwen2.5` matches both a 4.36 GiB and an 8.37 GiB build,
        and picking by response order made the budget depend on nothing. Under-sizing is the
        dangerous direction, so ambiguity resolves upward."""
        if self._model_bytes_cache != "unmeasured":
            return self._model_bytes_cache  # type: ignore[return-value]
        if models is None:
            models = self._models()
        if models is None:
            return None  # cache untouched: measure again once Ollama is back
        sizes = [m["size"] for m in models
                 if self._match(m.get("name", ""))
                 and isinstance(m.get("size"), int) and m["size"] > 0]
        if not sizes:
            # Not listed is not the same as measured-as-nothing: the model may simply not be pulled
            # YET. Caching this would leave the guard dead for the life of the client even after the
            # pull completed — which is the whole defect, and an empty list reaches here just as an
            # unreachable daemon does.
            return None
        self._model_bytes_cache = max(sizes)
        return self._model_bytes_cache

    def _resident(self) -> bool | None:
        """True when Ollama already holds this model in memory, None when it cannot be determined.

        A resident model is not about to be allocated again, so there is nothing for the preflight
        to prevent — and blocking there would break a conversation mid-turn over a load that is not
        going to happen. Two corrections:

        - The match must be EXACT, not the loose base-name match `_match` allows. An untagged
          `qwen2.5` reported "already loaded" because `qwen2.5:7b-instruct` was resident, while
          `chat` sends the untagged string and Ollama resolves it to `:latest` — a different blob,
          not loaded. The residency short-circuit runs before the size lookup, so the "resolve
          ambiguity upward" safety never got a chance to apply.
        - A failed probe returns None, not False. Reporting "not resident" when /api/ps timed out
          refused a load that was never going to happen, and did so in the one host state where the
          probe is most likely to time out."""
        try:
            ps = self._get("/api/ps", timeout=PROBE_TIMEOUT)
        except OllamaError:
            return None
        return any(m.get("name", "") == self.model for m in (ps.get("models") or []))

    def memory_status(self, models: list[dict] | None = None) -> tuple[str, str]:
        """A three-valued verdict: ("ok"|"unknown"|"refuse", message).

        Three values because two were not enough. `memory_preflight` returns None both when the
        load fits and when nothing could be measured — correct as *behaviour*, since the guard
        fails open by design, but `setup.sh doctor` rendered that None as a green "host can load
        <model>". On a fresh install, where the model is not pulled and therefore has no measurable
        size, the doctor cheerfully affirmed the opposite of the truth on the very machine that had
        lost its session. Failing open is right; claiming it fits is not.

        Ollama logs `system_limited=true` and loads anyway. This is the check nobody was doing.
        EVENTHOUND_ALLOW_LOW_MEMORY=1 proceeds anyway on a host you have judged yourself."""
        if hostmem is None:
            return ("unknown", "tools/hostmem is not importable in this deployment")
        if hostmem.override_active():
            return ("ok", f"memory check disabled by {hostmem.OVERRIDE_ENV}")
        resident = self._resident()
        if resident:
            return ("ok", f"{self.model} is already loaded")
        if resident is None:
            return ("unknown", "cannot tell whether the model is already loaded (/api/ps failed)")
        size = self._model_bytes(models)
        if not size:
            return ("unknown", f"cannot size '{self.model}' — Ollama unreachable, or not pulled yet")
        need = size * LOAD_OVERHEAD
        avail = hostmem.available_bytes()
        # The reserve, not bare availability: `available_bytes` is optimistic by construction on
        # macOS (inactive pages dominate it and a full compressor cannot release them), and the
        # incident's cost was paid by the OS rather than by the process that over-allocated — the
        # graphical session died, Ollama did not. Leaving the host a stated margin is the honest
        # answer to an estimate we know leans generous.
        reserve = hostmem.reserve_bytes()
        if avail is None:
            return ("unknown", "this host's free memory could not be measured")
        if avail - reserve < need:
            return ("refuse",
                    f"{self.model} needs about {need / hostmem.GIB:.1f} GiB to load. This host "
                    f"reports {avail / hostmem.GIB:.1f} GiB available, of which "
                    f"{reserve / hostmem.GIB:.1f} GiB is reserved for everything that is not the "
                    f"model, leaving {max(0.0, avail - reserve) / hostmem.GIB:.1f} GiB"
                    f"{hostmem.swap_note()}. Loading it now risks taking the session down. "
                    f"{self._remedy(models)}")
        # Swap pressure is NOT a gate — see tools/hostmem. It is reported inside the refusal above
        # when it applies, because "this host has been paging" is true and useful; it is not a
        # verdict, because macOS grows the swapfile on demand and the ratio therefore sits near its
        # ceiling on any machine that has ever paged.
        return ("ok", f"{need / hostmem.GIB:.1f} GiB needed, "
                      f"{(avail - reserve) / hostmem.GIB:.1f} GiB usable")

    def memory_preflight(self, models: list[dict] | None = None) -> str | None:
        """None when loading this model is safe on this host OR nothing could be measured, else the
        reason it is not. Fails open: an engine that refuses to run because it could not read
        `vm_stat` is a worse failure than the one being prevented. See `memory_status` for the
        verdict that keeps "fits" and "could not tell" apart."""
        state, message = self.memory_status(models)
        return message if state == "refuse" else None

    def _remedy(self, models: list[dict] | None = None) -> str:
        """What to actually do about it.

        The default-model suggestion is offered only when the default is MEASURABLY SMALLER than
        the model that just failed. Testing `self.model != DEFAULT_MODEL` was enough while the
        default was the larger of two; once it became the smallest NAMED model it stopped being
        the smallest possible one, and a refused `llama3.2:1b` was answered with "use
        EVENTHOUND_LLM_MODEL=qwen2.5:7b-instruct" — 3.5x the load that had just been declined.
        Advice that names a bigger allocation as the cure for running out of memory is worse than
        no advice. When either size cannot be measured the suggestion is dropped: silence is the
        safe direction. "Reboot" was dropped with the swap gate: it does not lower a ratio whose
        denominator macOS regrows."""
        steps = ["free memory"]
        if self.model != DEFAULT_MODEL and self._smaller_default(models):
            steps.append(f"use the default model (EVENTHOUND_LLM_MODEL={DEFAULT_MODEL})")
        steps.append("or set EVENTHOUND_ALLOW_LOW_MEMORY=1 to proceed anyway")
        # Upper-case the first letter only. `str.capitalize()` lower-cases everything after it,
        # which turned EVENTHOUND_LLM_MODEL into an environment variable that does not exist.
        text = ", ".join(steps)
        return text[:1].upper() + text[1:] + "."

    def _smaller_default(self, models: list[dict] | None = None) -> bool:
        """Is DEFAULT_MODEL measurably smaller than the configured one? False when either is
        unmeasurable — the caller must not suggest a swap it cannot show to be an improvement."""
        if models is None:
            models = self._models()
        if models is None:
            return False
        def size_of(name: str) -> int | None:
            sizes = [m["size"] for m in models
                     if m.get("name") == name and isinstance(m.get("size"), int) and m["size"] > 0]
            return min(sizes) if sizes else None
        mine, theirs = self._model_bytes(models), size_of(DEFAULT_MODEL)
        return bool(mine and theirs and theirs < mine)

    def unusable_reason(self) -> str | None:
        """Why the assistant cannot run right now, or None when it can.

        One question with one answer, because every gate asks it: the CLI, the GUI and the tests
        each checked `available()` alone, which knows whether the model is PULLED and nothing about
        whether it can be LOADED. The moment the memory guard existed, that gap showed up as an
        exception thrown past callers that believed they had already checked.

        One /api/tags round trip answers both halves; asking them separately issued the identical
        request twice, on the GUI's event loop."""
        models = self._models()
        if models is None or not self.available(models):
            return f"Ollama not reachable at {self.url}, or model '{self.model}' is not pulled"
        return self.memory_preflight(models)

    def _guard_memory(self) -> None:
        reason = self.memory_preflight()
        if reason:
            raise OllamaError(f"refusing to load a model: {reason}")

    # -- chat ---------------------------------------------------------------

    def chat(self, messages: list[dict], tools: list[dict] | None = None) -> dict:
        """One non-streaming chat turn. Returns the assistant `message` dict, which may
        carry `content` and/or `tool_calls`. Raises OllamaError on transport/HTTP failure, or
        when loading the model would not fit this host (`memory_preflight`)."""
        self._guard_memory()
        payload: dict = {"model": self.model, "messages": messages, "stream": False}
        if tools:
            payload["tools"] = tools
        data = self._post("/api/chat", payload)
        msg = data.get("message")
        if not isinstance(msg, dict):
            raise OllamaError(f"unexpected Ollama response (no message): {data!r:.200}")
        return msg

    def chat_stream(self, messages: list[dict], tools: list[dict] | None = None):
        """Streaming variant. Yields ('token', delta) for each content chunk as it arrives, then
        ('final', message_dict) once — the assembled assistant message (content + any tool_calls).

        Ollama streams NDJSON: one JSON object per line, each with a partial `message.content`;
        the object with `done: true` closes it. Tool calls arrive in a chunk (usually the last).

        The memory guard runs here too, not only in `chat`: these are the two calls that make
        Ollama allocate, and a guard placed at the call sites instead would be one forgotten
        caller away from useless."""
        self._guard_memory()
        payload: dict = {"model": self.model, "messages": messages, "stream": True}
        if tools:
            payload["tools"] = tools
        body = json.dumps(payload).encode()
        req = urllib.request.Request(self.url + "/api/chat", data=body,
                                     headers={"Content-Type": "application/json"}, method="POST")
        content = ""
        tool_calls: list = []
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as r:  # noqa: S310 — local URL
                for raw in r:
                    line = raw.strip()
                    if not line:
                        continue
                    obj = json.loads(line)
                    msg = obj.get("message") or {}
                    delta = msg.get("content") or ""
                    if delta:
                        content += delta
                        yield ("token", delta)
                    if msg.get("tool_calls"):
                        tool_calls = msg["tool_calls"]
        except urllib.error.HTTPError as e:
            detail = ""
            try:
                detail = e.read().decode()[:200]
            except Exception:
                pass
            raise OllamaError(f"Ollama HTTP {e.code} at {req.full_url} {detail}") from e
        except (urllib.error.URLError, TimeoutError, ConnectionError) as e:
            raise OllamaError(f"Ollama unreachable at {self.url} ({e})") from e
        except json.JSONDecodeError as e:
            raise OllamaError(f"Ollama returned non-JSON in stream ({e})") from e
        final = {"role": "assistant", "content": content}
        if tool_calls:
            final["tool_calls"] = tool_calls
        yield ("final", final)

    def tags(self) -> list[str]:
        """Names of the models pulled locally (for a model picker). [] if Ollama is unreachable.

        PROBE_TIMEOUT, not the chat timeout: this runs on the GUI's event loop, and at 180 s a
        thrashing-but-listening Ollama — the state the memory guard exists for — froze the whole
        interface. The same correction was made to the other probes and missed here."""
        try:
            data = self._get("/api/tags", timeout=PROBE_TIMEOUT)
        except OllamaError:
            return []
        return sorted(m.get("name", "") for m in (data.get("models") or []) if m.get("name"))

    # -- transport ----------------------------------------------------------

    def _post(self, path: str, payload: dict) -> dict:
        body = json.dumps(payload).encode()
        req = urllib.request.Request(self.url + path, data=body,
                                     headers={"Content-Type": "application/json"}, method="POST")
        return self._send(req)

    def _get(self, path: str, timeout: int | None = None) -> dict:
        req = urllib.request.Request(self.url + path, method="GET")
        return self._send(req, timeout=timeout)

    def _send(self, req: urllib.request.Request, timeout: int | None = None) -> dict:
        try:
            with urllib.request.urlopen(req, timeout=timeout or self.timeout) as r:  # noqa: S310
                return json.loads(r.read().decode())
        except urllib.error.HTTPError as e:
            detail = ""
            try:
                detail = e.read().decode()[:200]
            except Exception:
                pass
            raise OllamaError(f"Ollama HTTP {e.code} at {req.full_url} {detail}") from e
        except (urllib.error.URLError, TimeoutError, ConnectionError) as e:
            raise OllamaError(f"Ollama unreachable at {self.url} ({e})") from e
        except json.JSONDecodeError as e:
            raise OllamaError(f"Ollama returned non-JSON ({e})") from e
