"""Exercise deployment bulk frames over real loopback Peer streams."""
import asyncio
from contextlib import suppress
from hashlib import sha256
import unittest

from spearmint.peer.protocol import parse_b64, wire_b64
from spearmint.peer.session import Session


class DeploymentTransferTest(unittest.IsolatedAsyncioTestCase):
    async def test_parallel_chunks_keep_heartbeat_and_normal_rpc_available(self):
        payload = bytes(range(256)) * 1024
        handled = []
        tasks = []
        writers = []

        async def handler(method, params):
            if method == 'grove.deploy.upload':
                data = parse_b64(params['body']['data'], len(payload))
                self.assertEqual(sha256(data).hexdigest(), params['body']['sha256'])
                handled.append(params['body']['offset'])
                return {'received_bytes': len(handled) * len(data)}
            return {'ok': True}

        def accept(reader, writer):
            writers.append(writer)
            tasks.append(asyncio.create_task(Session(reader, writer, handler).run()))

        server = await asyncio.start_server(accept, '127.0.0.1', 0)
        try:
            reader, writer = await asyncio.open_connection('127.0.0.1', server.sockets[0].getsockname()[1])
            writers.append(writer)
            session = Session(reader, writer, handler)
            tasks.append(asyncio.create_task(session.run()))
            def params(index):
                return {'identity': ['fixture', 'admin', 1, 0, 0], 'action': 'write', 'body': {
                    'job': 'a' * 32, 'offset': index * len(payload), 'data': wire_b64(payload), 'sha256': sha256(payload).hexdigest()}}
            results = await asyncio.gather(session.call('grove.deploy.upload', params(0)),
                                           session.call('grove.deploy.upload', params(1)), session.call('peer.ping', {}))
            self.assertEqual(sorted(handled), [0, len(payload)])
            self.assertEqual(results[-1], {'ok': True})
            self.assertFalse(session.closed)
        finally:
            for task in tasks:
                task.cancel()
            for writer in writers:
                writer.close()
            for task in tasks:
                with suppress(BaseException):
                    await task
            server.close()
            await server.wait_closed()
