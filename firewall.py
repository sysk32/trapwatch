"""
Trapwatch
A drop-in defense layer that detects and neutralizes prompt injection attacks
hidden in web pages before they reach AI agents.

Inspired by Google DeepMind's "AI Agent Traps" paper (March 2026).
https://papers.ssrn.com/sol3/papers.cfm?abstract_id=6372438

Usage:
    from firewall import ContentFirewall

    fw = ContentFirewall(log_path="firewall.jsonl")

    # Sanitize text content
    clean_text, detections = fw.sanitize(raw_text, url="https://example.com")

    # Get JS to inject into page BEFORE extracting text (DOM-level sanitization)
    js = fw.get_dom_sanitizer_js()
"""

import json
import os
import re
from datetime import datetime
from typing import Optional


# Default injection patterns — covers the 6 attack categories from the DeepMind paper
DEFAULT_PATTERNS = [
    # Category 1: Instruction Override
    # Attacker tries to make the agent ignore its system prompt
    (r'(?i)ignore\s+(all\s+)?(?:prior|previous|above|earlier)\s+instructions?', 'instruction_override'),
    (r'(?i)disregard\s+(all\s+)?(?:prior|previous|above|earlier)\s+instructions?', 'instruction_override'),
    (r'(?i)forget\s+(all\s+)?(?:prior|previous|above|earlier)\s+instructions?', 'instruction_override'),
    (r'(?i)override\s+(all\s+)?(?:prior|previous|above|earlier)\s+instructions?', 'instruction_override'),
    (r'(?i)do\s+not\s+follow\s+(?:any\s+)?(?:prior|previous|above|earlier)\s+instructions?', 'instruction_override'),

    # Category 2: System Prompt Injection
    # Attacker embeds fake system prompts in web content
    (r'(?i)(?:^|\n)\s*system\s*:\s*.{10,}', 'system_prompt'),
    (r'(?i)\[SYSTEM\].*?\[/SYSTEM\]', 'system_prompt'),
    (r'(?i)<\s*system\s*>.*?<\s*/\s*system\s*>', 'system_prompt'),
    (r'(?i)BEGIN\s+SYSTEM\s+PROMPT', 'system_prompt'),

    # Category 3: Role Hijacking
    # Attacker tries to redefine the agent's identity or behavior
    (r'(?i)you\s+are\s+now\s+(?:a|an|the)\s+', 'role_hijack'),
    (r'(?i)act\s+as\s+(?:a|an|the)\s+', 'role_hijack'),
    (r'(?i)pretend\s+(?:you\s+are|to\s+be)\s+', 'role_hijack'),
    (r'(?i)from\s+now\s+on\s*,?\s*you\s+(?:are|will|must|should)', 'role_hijack'),
    (r'(?i)switch\s+to\s+(?:a|an)?\s*(?:unrestricted|unfiltered|jailbroken)\s+mode', 'role_hijack'),

    # Category 4: Data Exfiltration
    # Attacker tries to make the agent leak sensitive data
    (r'(?i)(?:send|post|transmit|exfiltrate|upload)\s+(?:all\s+)?(?:(?:data|info|context|memory|conversation|history|content|messages?)\s*)+to', 'data_exfil'),
    (r'(?i)curl\s+.*?-d\s+.*?(?:api_key|token|password|secret)', 'data_exfil'),
    (r'(?i)(?:fetch|request|get)\s+(?:and\s+)?(?:send|forward|post)\s+.*?(?:key|token|password|credential)', 'data_exfil'),

    # Category 5: Tool/Agent Abuse
    # Attacker tries to make the agent execute tools or spawn sub-agents
    (r'(?i)(?:call|use|invoke|execute|run)\s+(?:the\s+)?(?:tool|function|command)\s+', 'tool_abuse'),
    (r'(?i)spawn\s+(?:a\s+)?(?:sub-?agent|worker|process)', 'agent_spawn'),
    (r'(?i)(?:create|start|launch)\s+(?:a\s+)?(?:new\s+)?(?:agent|subprocess|worker)', 'agent_spawn'),

    # Category 6: Hidden Instruction Markers
    # Attacker uses explicit markers to hide instructions
    (r'(?i)BEGIN\s+(?:HIDDEN|SECRET|PRIVATE)\s+INSTRUCTIONS?', 'hidden_instruction'),
    (r'(?i)IMPORTANT\s*:\s*(?:DO\s+NOT|NEVER)\s+(?:SHOW|REVEAL|DISPLAY)\s+THIS', 'hidden_instruction'),
    (r'(?i)THIS\s+(?:TEXT|MESSAGE|CONTENT)\s+IS\s+(?:HIDDEN|INVISIBLE|NOT\s+VISIBLE)', 'hidden_instruction'),
]


# JavaScript to inject into the page before extracting text content.
# Removes DOM elements commonly used to hide prompt injections from human viewers.
DOM_SANITIZER_JS = """
(() => {
    const clone = document.cloneNode(true);

    // Remove script/style/nav noise
    clone.querySelectorAll('script, style, noscript').forEach(el => el.remove());

    // Remove hidden elements (common injection vectors)
    clone.querySelectorAll('[style*="display:none"], [style*="display: none"]').forEach(el => el.remove());
    clone.querySelectorAll('[style*="visibility:hidden"], [style*="visibility: hidden"]').forEach(el => el.remove());
    clone.querySelectorAll('[style*="position:absolute"][style*="-9999"]').forEach(el => el.remove());
    clone.querySelectorAll('[style*="opacity:0"], [style*="opacity: 0"]').forEach(el => el.remove());
    clone.querySelectorAll('[style*="font-size:0"], [style*="font-size: 0"]').forEach(el => el.remove());
    clone.querySelectorAll('[aria-hidden="true"]').forEach(el => el.remove());

    // Strip HTML comments
    const walker = document.createTreeWalker(clone, NodeFilter.SHOW_COMMENT, null, false);
    const comments = [];
    while (walker.nextNode()) comments.push(walker.currentNode);
    comments.forEach(c => c.parentNode.removeChild(c));

    // Get clean text
    let text = clone.body ? clone.body.innerText : document.body.innerText;
    text = text.replace(/\\n{3,}/g, '\\n\\n').trim();
    return text;
})()
"""


class ContentFirewall:
    """Drop-in content sanitizer for MCP browser servers.

    Provides two layers of defense:
    1. DOM sanitization (JavaScript) — removes hidden elements before text extraction
    2. Text sanitization (Python) — detects and redacts prompt injection patterns

    Usage with any MCP browser server:

        fw = ContentFirewall()

        # Layer 1: Use this JS expression instead of raw innerText
        js = fw.get_dom_sanitizer_js()
        text = await cdp_evaluate(js)

        # Layer 2: Scan the extracted text
        clean_text, detections = fw.sanitize(text, url=page_url)

        if detections:
            print(f"Blocked {len(detections)} injection attempts")
    """

    def __init__(
        self,
        patterns: Optional[list] = None,
        log_path: Optional[str] = None,
        redact_marker: str = "[REDACTED: {label}]",
    ):
        """Initialize the firewall.

        Args:
            patterns: List of (regex_pattern, label) tuples. Defaults to built-in patterns.
            log_path: Path to JSONL log file for detections. None disables logging.
            redact_marker: Template for replacement text. {label} is replaced with pattern label.
        """
        raw_patterns = patterns or DEFAULT_PATTERNS
        self._patterns = [(re.compile(p), label) for p, label in raw_patterns]
        self._log_path = log_path
        self._redact_marker = redact_marker

    def sanitize(self, text: str, url: str = "") -> tuple[str, list[dict]]:
        """Sanitize text content by detecting and redacting prompt injections.

        Args:
            text: Raw text content from a web page.
            url: Source URL for logging.

        Returns:
            Tuple of (cleaned_text, list_of_detection_dicts).
        """
        detections = []
        cleaned = text

        for pattern, label in self._patterns:
            matches = list(pattern.finditer(cleaned))
            for match in reversed(matches):
                detections.append({
                    "timestamp": datetime.now().isoformat(),
                    "url": url,
                    "pattern": label,
                    "matched_text": match.group()[:200],
                    "position": match.start(),
                })
                marker = self._redact_marker.format(label=label)
                cleaned = cleaned[:match.start()] + marker + cleaned[match.end():]

        if detections and self._log_path:
            self._log_detections(detections)

        return cleaned, detections

    def get_dom_sanitizer_js(self) -> str:
        """Return JavaScript that extracts text with hidden elements removed.

        Use this as the expression in CDP Runtime.evaluate instead of
        raw document.body.innerText.
        """
        return DOM_SANITIZER_JS

    def add_pattern(self, pattern: str, label: str):
        """Add a custom detection pattern at runtime.

        Args:
            pattern: Regex pattern string.
            label: Label for this pattern type (used in logs and redaction markers).
        """
        self._patterns.append((re.compile(pattern), label))

    def _log_detections(self, detections: list[dict]):
        """Append detections to JSONL log file."""
        try:
            log_dir = os.path.dirname(self._log_path)
            if log_dir:
                os.makedirs(log_dir, exist_ok=True)
            with open(self._log_path, "a") as f:
                for d in detections:
                    f.write(json.dumps(d) + "\n")
        except Exception:
            pass


# Convenience function for quick usage
def sanitize(text: str, url: str = "", log_path: Optional[str] = None) -> tuple[str, list[dict]]:
    """Quick sanitize without instantiating a class.

    Args:
        text: Raw text content.
        url: Source URL for logging.
        log_path: Optional path to detection log.

    Returns:
        Tuple of (cleaned_text, detections).
    """
    fw = ContentFirewall(log_path=log_path)
    return fw.sanitize(text, url=url)
