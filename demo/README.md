# Demo files

Harmless test files for trying the crew in a room. Drop them into a channel where the crew is.

- `CLAUDE.md`: an agent rules file that looks clean but carries one line of invisible Unicode (Tags block). Inspector decodes it and Fixer posts a clean copy. The hidden line points at `example.invalid`, a domain that can never resolve.
- `weather_server.py`: a tiny MCP server whose tool description hides an `<IMPORTANT>` block asking the agent to read `~/.ssh/id_rsa`. This is the "tool poisoning" pattern. Nothing here runs or reads anything; it is text for Inspector to read.
- `mcp.json`: an MCP config with one misspelled server (`@modelcontextprotcol/...`). Scout stops it, Squat Watch watches the name, Fixer swaps in the real package.
