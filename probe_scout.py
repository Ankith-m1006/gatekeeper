import asyncio, logging, os
from gatekeeper.switch import Agent, Event
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(message)s")
env=dict(l.strip().split('=',1) for l in open('.env') if '=' in l)
a=Agent(name="scout", display_name="Scout", description="Gatekeeper crew: catches every new package mentioned in the room and checks it live on npm and PyPI.", api=env['SWITCH_API'], registration_token=env['SWITCH_REGISTRATION_TOKEN'])
async def main():
    await a.ensure_registered()
    print("registered", a.agent_id)
    print("rooms", await a.op("list_rooms"))
    async def h(ev: Event):
        print("EVENT", ev.type, ev.room_id, ev.addressed, ev.sender, ev.body[:120])
    await asyncio.wait_for(a.run(h), timeout=float(os.environ.get("T","25")))
try: asyncio.run(main())
except asyncio.TimeoutError: print("timeout ok")
