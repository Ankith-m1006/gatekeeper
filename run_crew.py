"""Start the Gatekeeper crew: four Switch agents, each with its own identity and connection.

They hand work to each other only through Switch (targeted messages and room documents), so each
one can also run on its own machine:  python -u run_crew.py scout   (or inspector, squat-watch, fixer)
"""
import asyncio, logging, sys
from gatekeeper.switch import Agent
from gatekeeper.crew import RoomPolicy
from gatekeeper.scout import Scout
from gatekeeper.inspector import Inspector
from gatekeeper.squat_watch import SquatWatch
from gatekeeper.fixer import Fixer

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
logging.getLogger("httpx").setLevel(logging.WARNING)
env = dict(l.strip().split("=", 1) for l in open(".env") if "=" in l)

CREW = {
    "scout": ("Scout", "Catches every new package your team or its coding agents bring in, and checks it live on npm and PyPI."),
    "inspector": ("Inspector", "Reads the code of risky packages without ever running it."),
    "squat-watch": ("Squat Watch", "Remembers package names your agents invented and alerts the moment someone registers one."),
    "fixer": ("Fixer", "Rewrites bad installs into safe ones, keeps the room's rules and holds the human approval gate."),
}


async def main(names):
    jobs = []
    for name in names:
        display, desc = CREW[name]
        a = Agent(name=name, display_name=display, description=desc, api=env["SWITCH_API"], registration_token=env["SWITCH_REGISTRATION_TOKEN"])
        await a.ensure_registered()
        if name == "scout":
            jobs.append(a.run(Scout(a, RoomPolicy()).on_event))
        elif name == "inspector":
            jobs.append(a.run(Inspector(a).on_event))
        elif name == "squat-watch":
            sw = SquatWatch(a)
            jobs += [a.run(sw.on_event), sw.watch_forever(), sw.publish_on_start()]
        elif name == "fixer":
            fx = Fixer(a, RoomPolicy())
            jobs += [a.run(fx.on_event), fx.publish_on_start()]
    await asyncio.gather(*jobs)


asyncio.run(main(sys.argv[1:] or list(CREW)))
