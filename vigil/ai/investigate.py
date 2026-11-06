"""An AI investigation with read-only lookups (ai/tools.py): Claude asks for findings,
pivots and storylines as it goes, instead of getting one fixed bundle.

SWITCHED OFF. CLAUDE.md's AI rule says the model gets no tools, so no command or page
that reaches the live API uses this yet: LOOKUPS_ENABLED stays False until the owner
changes that rule (docs/PROGRESS.md, round 3, "Open decision"). The loop and the lookups
are built and tested against a scripted stub of the SDK, so turning it on is one line.

The loop (a manual one, so every lookup passes through Vigil's own checks):
- each request carries the strict tool definitions; tool_choice stays "auto";
- the assistant's content goes back unchanged (thinking blocks included);
- every tool_use in a turn is answered in one user message, failures as is_error;
- refusal, max_tokens and the lookup cap end the run with a plain note;
- the answer is checked against the commands Vigil generated for the findings it read.
"""

import time

from . import context, providers
from .tools import Lookups, definitions

LOOKUPS_ENABLED = False      # the owner's decision; see the module docstring
OFF_NOTE = ("Investigations with lookups are built but switched off: Vigil's rules (CLAUDE.md) say the model gets "
            "no tools. If you want the model to look things up (read-only), change that rule, then set "
            "LOOKUPS_ENABLED = True in vigil/ai/investigate.py.")
MAX_TURNS = 10
SYSTEM_LOOKUPS = providers.SYSTEM.replace(
    "The evidence is one JSON document between the tags <{boundary}> and </{boundary}>.",
    "You can look things up with read-only tools over Vigil's findings. Every tool result is a JSON document "
    "between the tags <{boundary}> and </{boundary}>.") + """

Start from the storylines and the High findings; open a finding before you make a claim about it, and pivot on \
its program, file, address or package to see what else touches it. Stop when you can answer; a handful of \
lookups is usually enough. Name the findings you relied on by title."""


def _blocks(content):
    return [b for b in content or [] if getattr(b, "type", None) == "tool_use"]


def run(question, lookups, client=None, model=providers.MODEL, max_turns=MAX_TURNS):
    """Investigate `question` with `lookups` (a tools.Lookups). Returns a result dict; raises ProviderError."""
    messages = [{"role": "user", "content": f"My question: {question}"}]
    system = SYSTEM_LOOKUPS.format(boundary=lookups.boundary)
    usage = {"input_tokens": 0, "output_tokens": 0}
    t0, turns, note, refused, response = time.time(), 0, None, False, None
    while True:
        turns += 1
        response = providers.create(client, model=model, max_tokens=16000, system=system, tools=definitions(),
                                    messages=messages)
        u = providers._usage(response)
        for k in usage:
            usage[k] += u.get(k) or 0
        if response.stop_reason == "refusal":
            cat = getattr(getattr(response, "stop_details", None), "category", None)
            refused, note = True, f"The model declined (category: {cat or 'unknown'}). The offline brief still applies."
            break
        if response.stop_reason == "pause_turn":
            messages.append({"role": "assistant", "content": response.content})
            continue
        uses = _blocks(response.content)
        if response.stop_reason != "tool_use" or not uses:
            if response.stop_reason == "max_tokens":
                note = "The answer was cut off at the length limit."
            break
        messages.append({"role": "assistant", "content": response.content})
        if turns >= max_turns:
            note = f"Stopped after {turns} rounds of lookups; the answer below is what the model had by then."
            messages.append({"role": "user", "content": [
                {"type": "tool_result", "tool_use_id": b.id, "is_error": True,
                 "content": "Lookup limit reached: answer now with what you have."} for b in uses]})
            response = providers.create(client, model=model, max_tokens=16000, system=system, tools=definitions(),
                                        messages=messages)
            u = providers._usage(response)
            for k in usage:
                usage[k] += u.get(k) or 0
            break
        results = []
        for b in uses:
            text, err = lookups.call(b.name, b.input if isinstance(b.input, dict) else {})
            results.append({"type": "tool_result", "tool_use_id": b.id, "content": text, **({"is_error": True} if err else {})})
        messages.append({"role": "user", "content": results})
    answer = "" if refused else "\n".join(b.text for b in response.content
                                          if getattr(b, "type", None) == "text").strip()
    return {"answer": answer, "refused": refused, "note": note, "model": getattr(response, "model", model),
            "turns": turns, "lookups": [{k: c[k] for k in ("name", "input", "bytes", "ms") if k in c}
                                        | ({"error": c["error"]} if c.get("error") else {}) for c in lookups.calls],
            "findings_read": len(lookups.seen), "injection": lookups.injection,
            "redactions": lookups.redactor.count, "not_from_vigil": context.command_provenance(answer, lookups.commands),
            "usage": usage, "seconds": round(time.time() - t0, 1),
            "bytes_sent": sum(c["bytes"] for c in lookups.calls) + len(question.encode())}


def investigate(store, data_root, question, redact=True, client=None, **kw):
    """Run, and log it in Cases' AI log like an Ask (scope 'investigate'). Refuses while switched off."""
    if not LOOKUPS_ENABLED:
        raise providers.ProviderError(OFF_NOTE)
    lk = Lookups(store, data_root, redact=redact)
    row = {"provider": "claude+lookups", "model": providers.MODEL, "scope": "investigate (read-only lookups)",
           "question": question[:2000], "bytes_sent": 0, "findings": 0, "redactions": 0}
    try:
        out = run(question, lk, client=client, **kw)
    except providers.ProviderError as exc:
        row.update(bytes_sent=sum(c["bytes"] for c in lk.calls), findings=len(lk.seen), redactions=lk.redactor.count)
        store.log_ai(row, error=str(exc), usage={"lookups": lk.calls})
        raise
    row.update(model=out["model"], bytes_sent=out["bytes_sent"], findings=out["findings_read"],
               redactions=out["redactions"])
    store.log_ai(row, answer=out["answer"], refused=out["refused"], usage=dict(out["usage"], lookups=out["lookups"]))
    return out
