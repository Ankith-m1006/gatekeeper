"""Start the Gatekeeper crew: each agent keeps its own Switch connection."""
import asyncio, logging
from gatekeeper.switch import Agent
from gatekeeper.scout import Scout

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
logging.getLogger("httpx").setLevel(logging.WARNING)
env = dict(l.strip().split("=", 1) for l in open(".env") if "=" in l)

def agent(name, display, desc):
    return Agent(name=name, display_name=display, description=desc, api=env["SWITCH_API"], registration_token=env["SWITCH_REGISTRATION_TOKEN"])

async def main():
    scout = agent("scout", "Scout", "Catches every new package your team or its coding agents bring in, and checks it live on npm and PyPI.")
    await scout.ensure_registered()
    await asyncio.gather(scout.run(Scout(scout).on_event))

asyncio.run(main())
