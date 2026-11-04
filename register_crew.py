"""Register the Gatekeeper crew once (owned by whoever made the registration key)."""
import asyncio
from gatekeeper.switch import Agent
from gatekeeper.crew import settings
env = settings()
CREW = [
    ("scout", "Scout", "Catches every new package your team or its coding agents bring in, and checks it live on npm and PyPI."),
    ("inspector", "Inspector", "Opens suspicious packages in a sandbox, without running them, and reports install scripts, network calls and hidden code."),
    ("squat-watch", "Squat Watch", "Remembers package names your agents made up, and alerts the room the moment someone registers one."),
    ("fixer", "Fixer", "Finds the real package that does the job and proposes the swap."),
]
async def main():
    for name, display, desc in CREW:
        a = Agent(name=name, display_name=display, description=desc, api=env["SWITCH_API"], registration_token=env["SWITCH_REGISTRATION_TOKEN"])
        await a.ensure_registered()
        ctx = await a.op("get_my_context", _bind=False)
        print(name, a.agent_id, "owner:", ctx["person"]["name"])
if __name__ == "__main__":
    asyncio.run(main())
