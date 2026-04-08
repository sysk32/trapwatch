# Trapwatch

A drop-in defense layer that detects and neutralizes prompt injection attacks hidden in web pages before they reach AI agents.

Built in response to Google DeepMind's ["AI Agent Traps"](https://papers.ssrn.com/sol3/papers.cfm?abstract_id=6372438) paper (March 2026), which identifies six categories of adversarial content designed to manipulate AI agents browsing the web.

## The Problem

When AI agents browse the web, they consume raw page content — including hidden elements invisible to humans but parsed by machines. Attackers can embed prompt injections in:

- HTML comments (`<!-- Ignore prior instructions -->`)
- Hidden CSS elements (`display:none`, `opacity:0`, offscreen positioning)
- ARIA attributes (`aria-hidden`, `aria-label`)
- Invisible text (zero font size, matching background color)

These "agent traps" can override safety guidelines, exfiltrate data, or hijack agent behavior — all while the page looks completely normal to a human reviewer.

## How It Works

Two-layer defense:

**Layer 1 — DOM Sanitization (JavaScript)**
Runs inside the browser before text extraction. Removes hidden DOM elements that could contain injections:
- `display:none` / `visibility:hidden` elements
- Offscreen positioned elements (`left: -9999px`)
- Zero opacity / zero font-size elements
- `aria-hidden="true"` elements  
- HTML comments

**Layer 2 — Text Sanitization (Python)**
Scans extracted text for 20+ prompt injection patterns across 6 categories:
- Instruction overrides ("ignore prior instructions")
- System prompt injection (`[SYSTEM]`, `<system>`)
- Role hijacking ("you are now a...", "pretend to be")
- Data exfiltration attempts ("send all data to...")
- Tool/agent abuse ("spawn a sub-agent", "execute the tool")
- Hidden instruction markers ("BEGIN HIDDEN INSTRUCTIONS")

Matched content is replaced with `[REDACTED: pattern_type]` so the agent knows something was stripped.

## Quick Start

```python
from firewall import ContentFirewall

fw = ContentFirewall(log_path="detections.jsonl")

# Layer 1: Use this JS instead of raw innerText in your CDP calls
js = fw.get_dom_sanitizer_js()
# text = await cdp_evaluate(js)

# Layer 2: Scan the extracted text
clean_text, detections = fw.sanitize(raw_text, url="https://example.com")

if detections:
    print(f"Blocked {len(detections)} injection attempts")
    for d in detections:
        print(f"  [{d['pattern']}] {d['matched_text'][:80]}")
```

## Integration with MCP Browser Servers

Drop the firewall into your existing MCP browser server's `get_content` handler:

```python
from firewall import ContentFirewall

fw = ContentFirewall(log_path="firewall.jsonl")

# In your get_content tool handler:
async def handle_get_content():
    # Layer 1: Use sanitizing JS for text extraction
    result = await cdp_send(ws_url, "Runtime.evaluate", {
        "expression": fw.get_dom_sanitizer_js(),
        "returnByValue": True
    })
    text = result["result"]["value"]
    
    # Layer 2: Scan for text-level injections
    text, detections = fw.sanitize(text, url=current_url)
    
    if detections:
        text = f"WARNING: {len(detections)} injection(s) redacted\n\n" + text
    
    return text
```

## Custom Patterns

Add your own detection patterns:

```python
fw = ContentFirewall()

# Add a custom pattern
fw.add_pattern(r'(?i)send.*?to\s+https?://(?!trusted\.com)', 'untrusted_exfil')
```

## Detection Log

When `log_path` is set, all detections are logged as JSONL:

```json
{
  "timestamp": "2026-04-07T21:30:00",
  "url": "https://example.com/article",
  "pattern": "instruction_override", 
  "matched_text": "ignore all prior instructions",
  "position": 1423
}
```

## What It Catches

Based on the DeepMind "AI Agent Traps" taxonomy:

| Attack Type | Layer 1 (DOM) | Layer 2 (Text) |
|---|---|---|
| Hidden HTML comments | Yes | - |
| CSS-hidden elements | Yes | - |
| Offscreen positioned text | Yes | - |
| Invisible text (opacity/font) | Yes | - |
| Instruction overrides | - | Yes |
| System prompt injection | - | Yes |
| Role hijacking | - | Yes |
| Data exfiltration prompts | - | Yes |
| Tool/agent abuse | - | Yes |

## What It Doesn't Catch

- Semantic manipulation (biased but visible language)
- Steganographic payloads in images
- Contextual framing attacks
- Novel injection patterns not in the pattern list

This is a defense-in-depth layer, not a silver bullet. Combine with permission controls, human review, and principle of least privilege.

## License

MIT

## References

- Franklin, M. et al. "AI Agent Traps." Google DeepMind, March 2026. [SSRN 6372438](https://papers.ssrn.com/sol3/papers.cfm?abstract_id=6372438)
