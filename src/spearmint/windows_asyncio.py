"""Complete Windows socket teardown when the peer has already reset the connection."""
from asyncio import ProactorEventLoop
from asyncio.proactor_events import _ProactorSocketTransport
from errno import WSAECONNRESET
from socket import SHUT_RDWR


class _PanelSocketTransport(_ProactorSocketTransport):
    def _call_connection_lost(self, exc):
        if self._called_connection_lost:
            return
        try:
            self._protocol.connection_lost(exc)
        finally:
            sock, server = self._sock, self._server
            try:
                if sock.fileno() != -1:
                    sock.shutdown(SHUT_RDWR)
            except ConnectionResetError as error:
                if getattr(error, 'winerror', None) != WSAECONNRESET:
                    raise
            finally:
                try:
                    sock.close()
                finally:
                    self._sock = self._server = None
                    self._called_connection_lost = True
                    if server is not None:
                        server._detach()


class _PanelProactorEventLoop(ProactorEventLoop):
    def _make_socket_transport(self, sock, protocol, waiter=None, extra=None, server=None):
        return _PanelSocketTransport(self, sock, protocol, waiter, extra, server)


def loop_factory() -> ProactorEventLoop:
    return _PanelProactorEventLoop()
