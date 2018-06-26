import asyncio
from functools import partial
import logging
import struct
import socket
import uvloop
import weakref

from .auth import AuthenticationError, UsernamePassword, WithoutAuth


__all__ = (
    'create_server', 'Socks5'
)


logger = logging.getLogger('socksio')


class SocksReply:

    SUCCESS = 0x00
    GENERAL_SOCKS_SERVER_FAILURE = 0x01
    CONNECTION_NOT_ALLOWED_BY_RULESET = 0x02
    COMMAND_NOT_SUPPORTED = 0x07


class SocksConnectionType:

    CONNECT = 0x01
    BIND = 0x02
    UDP_ASSOCIATE = 0x03


class RemoteConnection(asyncio.Protocol):

    def __init__(self, proxy_transport):
        self._transport = None
        self._proxy_transport = weakref.proxy(proxy_transport)

    def connection_made(self, transport):
        self._transport = transport

    def connection_lost(self, exc):
        self._transport.close()
        if not self._proxy_transport.is_closing():
            self._proxy_transport.close()

    def data_received(self, data):
        self._proxy_transport.write(data)


class Socks5(asyncio.StreamReaderProtocol):

    IPV4 = 1
    DOMAINNAME = 3
    IPV6 = 4

    VERSION = 5

    def __init__(self, auth_handlers=None, **kwargs):
        self._loop = kwargs.get('loop', asyncio.get_event_loop())
        super().__init__(
            asyncio.StreamReader(loop=self._loop), loop=self._loop
        )
        if auth_handlers is not None:
            self._auth_handlers = {auth.METHOD: auth for auth in auth_handlers}
        else:
            self._auth_handlers = {
                WithoutAuth.METHOD: WithoutAuth(self.VERSION)
            }
        self._connection_type_handlers = {
            SocksConnectionType.CONNECT: self._connect
        }
        self._transport = None
        self._remote = None
        self._close_event = asyncio.Event()
        self._worker = None

    def connection_made(self, transport):
        logger.info('Accepting connection from: {}:{}.'.format(
            *transport.get_extra_info('peername'))
        )
        self._transport = transport
        super().connection_made(transport)
        self._stream_writer = asyncio.StreamWriter(
            self._transport, self, self._stream_reader, self._loop
        )
        asyncio.ensure_future(self.serve_connection())

    def connection_lost(self, exc):
        self._close_event.set()
        if self._worker:
            self._worker.cancel()
        if self._remote and not self._remote.is_closing():
            self._remote.close()

    async def serve_connection(self):
        try:
            await self.authenticate()
        except AuthenticationError:
            logger.warning(
                'Client {}:{} failed the authorization'.format(
                    *self._transport.get_extra_info('peername')
                )
            )
            self._transport.close()
        else:
            await self._handle_connection_by_type()
            self._worker = asyncio.ensure_future(self._start_exchange_loop())

    async def authenticate(self):
        """Handle client auth

        Client should send to the server the following format message:

        +----+----------+----------+
        |VER | NMETHODS | METHODS  |
        +----+----------+----------+
        | 1  |    1     | 1 to 255 |
        +----+----------+----------+

        Where:
            VER - version of the protocol (For SOCKS5 it should be 0x05)
            NMETHODS - the number of method identifier octets that appear
                       in the METHODS field.
            METHODS -
        """
        # Get version and number of auth methods
        client_info = await self._stream_reader.read(2)
        version, nmethods = struct.unpack('!BB', client_info)
        if version != self.VERSION:
            self._transport.close()
        client_methods = struct.unpack(
            'B' * nmethods, await self._stream_reader.read(nmethods)
        )
        auth_methods = set(self._auth_handlers) & set(client_methods)
        # TODO: Create the auth strategy
        await self._auth_handlers[auth_methods.pop()].negotiate(
            self._stream_reader, self._stream_writer
        )

    async def _handle_connection_by_type(self):
        version, cmd, rsv, atyp = struct.unpack(
            '!BBBB', await self._stream_reader.read(4)
        )
        handler = self._connection_type_handlers.get(cmd)
        if handler is None:
            self._stream_writer.write(
                struct.pack(
                    '!BB', self.VERSION, SocksReply.COMMAND_NOT_SUPPORTED
                )
            )
            self._transport.close()
        else:
            remote_addr = socket.inet_ntoa(await self._stream_reader.read(4))
            remote_port = struct.unpack('!H', await self._stream_reader.read(2))[0]
            await handler(atyp, remote_addr, remote_port)

    async def _connect(self, atyp, remote_addr, remote_port):
        remote_transport, remote_client = await self._loop.create_connection(
            partial(RemoteConnection, self._transport),
            remote_addr, remote_port
        )
        self._remote = remote_transport
        bind_addr, bind_port = remote_transport.get_extra_info('sockname')
        self._stream_writer.write(struct.pack('!BBBB', 5, 0, 0, atyp))
        self._stream_writer.write(
            socket.inet_aton(bind_addr) + struct.pack('!H', bind_port)
        )

    async def _bind(self): pass

    async def _udp_associate(self): pass

    async def _start_exchange_loop(self):
        while not self._close_event.is_set():
            try:
                data = await self._stream_reader.read(2048)
                if not data:
                    self._close_event.set()
                else:
                    self._remote.write(data)
            except Exception as exc:
                logger.exception(exc)

    async def stop(self):
        self._close_event.set()


async def create_server(host, port, loop=None):
    loop = loop if loop is not None else asyncio.get_event_loop()
    await loop.create_server(Socks5, host, port)
