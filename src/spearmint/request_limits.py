"""Bound HTTP request bodies before a framework or endpoint buffers them."""
from starlette.exceptions import HTTPException
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send


AUTH_BODY_LIMIT = 32 * 1024
API_BODY_LIMIT = 256 * 1024
DETAIL = 'Request body exceeds its size limit'


class RequestBodyLimit:
    def __init__(self, app: ASGIApp):
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope['type'] != 'http':
            await self.app(scope, receive, send)
            return
        path = scope['path']
        # The other API endpoints include bounded archive chunks and Grove
        # invitations carrying the members' public certificates.
        auth_path = path in {'/api/v1/session', '/api/v1/setup'} or path.startswith('/api/v1/auth/')
        # Quorum join uses bounded signed enrollment material rather than a login JSON model.
        maximum = AUTH_BODY_LIMIT if auth_path and not path.startswith('/api/v1/auth/grove/quorum-join/') else API_BODY_LIMIT
        lengths = [value for name, value in scope['headers'] if name == b'content-length']
        if lengths:
            length = lengths[0]
            if len(lengths) != 1 or not length.isdigit():
                await JSONResponse({'detail': 'Invalid Content-Length'}, status_code=400)(scope, receive, send)
                return
            # Avoid converting an attacker-controlled integer with an arbitrary number of digits.
            significant = length.lstrip(b'0')
            if len(significant) > len(str(maximum)) or int(significant or b'0') > maximum:
                await JSONResponse({'detail': DETAIL}, status_code=413)(scope, receive, send)
                return

        size = 0

        async def limited_receive() -> Message:
            nonlocal size
            message = await receive()
            if message['type'] == 'http.request':
                size += len(message.get('body', b''))
                if size > maximum:
                    raise HTTPException(413, DETAIL)
            return message

        await self.app(scope, limited_receive, send)
