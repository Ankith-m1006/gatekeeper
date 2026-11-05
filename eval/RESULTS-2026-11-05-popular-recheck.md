# Gatekeeper eval (05 Nov 2026)

## npm
- Real malware read: 0. Called **malicious-looking**: 0 (n/a). Flagged at all (risky or worse): 0 (n/a).
- Popular real packages read: 498. Wrongly called malicious-looking: 1 (0.2%). Asked for a human look (risky): 1 (0.2%).
- Malware names one typo from a top-3000 package: 0 of 0.

What the malware did, as Inspector saw it: 
False alarms to study: esbuild (runs shell commands, sends machine or user details out during install)

## pypi
- Real malware read: 0. Called **malicious-looking**: 0 (n/a). Flagged at all (risky or worse): 0 (n/a).
- Popular real packages read: 489. Wrongly called malicious-looking: 8 (1.6%). Asked for a human look (risky): 57 (11.7%).
- Malware names one typo from a top-3000 package: 0 of 0.

What the malware did, as Inspector saw it: 
False alarms to study: ddtrace (builds and runs code at runtime, collects environment variables in bulk), litellm (builds and runs code at runtime, collects environment variables in bulk), httplib2 (hides code that phones home on import), reportlab (builds and runs code at runtime, runs shell commands), tqdm (runs shell commands, sends data to a Discord or Telegram webhook), fastmcp-slim (collects environment variables in bulk, downloads something and runs it), psutil (collects environment variables in bulk, fingerprints the machine), huggingface-hub (builds and runs code at runtime, collects environment variables in bulk)

Unreadable (download or archive errors, left out of the numbers above): 13.