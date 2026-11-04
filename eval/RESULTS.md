# Gatekeeper eval (04 Nov 2026)

## npm
- Real malware read: 200. Called **malicious-looking**: 76 (38.0%). Flagged at all (risky or worse): 121 (60.5%).
- Popular real packages read: 500. Wrongly called malicious-looking: 1 (0.2%). Asked for a human look (risky): 4 (0.8%).
- Malware names one typo from a top-3000 package: 1 of 200.

What the malware did, as Inspector saw it: runs shell commands (88); fingerprints the machine (51); sends data to a known data-collection service (47); sends machine or user details out during install (46); talks to a raw IP address (14); goes online during install (13); looks obfuscated (12); builds and runs code at runtime (10)
False alarms to study: psl (sends data to a known data-collection service)

## pypi
- Real malware read: 196. Called **malicious-looking**: 138 (70.4%). Flagged at all (risky or worse): 165 (84.2%).
- Popular real packages read: 470. Wrongly called malicious-looking: 7 (1.5%). Asked for a human look (risky): 39 (8.3%).
- Malware names one typo from a top-3000 package: 17 of 196.

What the malware did, as Inspector saw it: runs shell commands (111); downloads something and runs it (47); sends data to a known data-collection service (40); fingerprints the machine (38); sends machine or user details out during install (34); setup.py replaces the install step with its own code (32); sends data to a Discord or Telegram webhook (20); builds and runs code at runtime (19)
False alarms to study: pywin32 (builds and runs code at runtime, fingerprints the machine), ansible-core (builds and runs code at runtime, collects environment variables in bulk), claude-agent-sdk (downloads something and runs it, fingerprints the machine), streamlit (builds and runs code at runtime, runs shell commands), mlflow (builds and runs code at runtime, collects environment variables in bulk), configargparse (runs shell commands, sends machine or user details out during install), yt-dlp (builds and runs code at runtime, collects environment variables in bulk)

Unreadable (download or archive errors, left out of the numbers above): 34.