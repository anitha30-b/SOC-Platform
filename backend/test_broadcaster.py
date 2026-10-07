import asyncio

from realtime_broadcaster import SecurityEventBroadcaster


async def test():
    broadcaster = SecurityEventBroadcaster()

    queue = broadcaster.subscribe()

    event = {
        "event_id": "test-1",
        "severity": "ERROR",
        "message": "Test SOC event",
    }

    broadcaster.publish(event)

    received = await queue.get()

    print("BROADCAST:", received)

    broadcaster.unsubscribe(queue)


asyncio.run(test())