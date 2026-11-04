"""Start the Gatekeeper crew: four Switch agents, each with its own connection and identity."""
import asyncio, logging
from gatekeeper.switch import Agent
from gatekeeper.crew import Board, RoomPolicy
from gatekeeper.scout import Scout
from gatekeeper.inspector import Inspector, render
from gatekeeper.inspect_pkg import inspect
from gatekeeper.squat_watch import SquatWatch
from gatekeeper.fixer import Fixer

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
logging.getLogger("httpx").setLevel(logging.WARNING)
env = dict(l.strip().split("=", 1) for l in open(".env") if "=" in l)

def agent(name, display, desc):
    return Agent(name=name, display_name=display, description=desc, api=env["SWITCH_API"], registration_token=env["SWITCH_REGISTRATION_TOKEN"])

async def main():
    a = {
        "scout": agent("scout", "Scout", "Catches every new package your team or its coding agents bring in, and checks it live on npm and PyPI."),
        "inspector": agent("inspector", "Inspector", "Reads the code of risky packages without ever running it."),
        "squat-watch": agent("squat-watch", "Squat Watch", "Remembers package names your agents invented and alerts the moment someone registers one."),
        "fixer": agent("fixer", "Fixer", "Rewrites bad installs into safe ones and holds the human approval gate."),
    }
    for x in a.values():
        await x.ensure_registered()
    board, policy = Board(), RoomPolicy()
    inspector = Inspector(a["inspector"])

    async def inspect_new(room, eco, name):
        await a["inspector"].send(room, render(await inspect(eco, name)))

    squat = SquatWatch(a["squat-watch"], on_registered=inspect_new)
    fixer = Fixer(a["fixer"], policy)
    for crew_member in (inspector, squat, fixer):
        board.subscribe(crew_member.on_case)
    await asyncio.gather(
        a["scout"].run(Scout(a["scout"], board, policy).on_event),
        a["inspector"].run(inspector.on_event),
        a["squat-watch"].run(squat.on_event),
        a["fixer"].run(fixer.on_event),
        squat.watch_forever(),
    )

asyncio.run(main())
