import asyncio
from typing import Dict, List

class SSEController:
    def __init__(self):
        self.user_queues: Dict[str, asyncio.Queue] = {}

    async def create_user_queue(self, username: str):
        if username not in self.user_queues:
            self.user_queues[username] = asyncio.Queue()

    async def remove_user_queue(self, username: str):
        if username in self.user_queues:
            del self.user_queues[username]

    async def add_to_queue(self, username: str, data: dict):
        print(f"Attempting to add data to queue for user: {username}")
        if username in self.user_queues:
            print(f"Queue exists for {username}, adding data: {data}")
            await self.user_queues[username].put(data)
        else:
            print(f"No queue found for user: {username}. Available queues: {list(self.user_queues.keys())}")

    async def get_from_queue(self, username: str):
        if username in self.user_queues:
            # print(f"Getting data from queue for {username}...")
            try:
                # Use get_nowait() to avoid blocking indefinitely
                data = self.user_queues[username].get_nowait()
                # print(f"Got data from queue for {username}: {data}")
                return data
            except asyncio.QueueEmpty:
                return None
        return None

sse_controller = SSEController()
