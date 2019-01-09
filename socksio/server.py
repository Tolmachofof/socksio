import asyncio
import functools
import logging
import struct
import socket

from .auth import WithoutAuth
from .common import SOCKS_VERSION, SocksReply
from .exceptions import (
    ProxyError, UnsupportedCMD, UnsupportedAuthorizationType
)


class BaseCMD:
    """The base class is for """
    
    def __init__(self, proxy_reader, proxy_writer):
        self._proxy_reader = proxy_reader
        self._proxy_writer = proxy_writer
        
    async def serve(self):
        raise NotImplementedError
    
    
class ConnectCMD(BaseCMD):
    
    async def serve(self):
        remote_transport = await self._make_remote_transport()
        if remote_transport is not None:
            remote_reader, remote_writer = remote_transport
            await asyncio.gather(
                self._transfer(self._proxy_reader, remote_writer),
                self._transfer(remote_reader, self._proxy_writer)
            )
            remote_writer.close()
    
    async def _make_remote_transport(self):
        remote_host = socket.inet_ntoa(await self._proxy_reader.read(4))
        remote_port = struct.unpack('!H', await self._proxy_reader.read(2))[0]
        try:
            return await asyncio.wait_for(
                asyncio.open_connection(remote_host, remote_port), 1
            )
        except asyncio.TimeoutError as exc:
            logging.exception(exc)
    
    @staticmethod
    async def _transfer(reader, writer):
        try:
            data = await reader.read(1024)
            while data:
                writer.write(data)
                data = await reader.read(1024)
        except OSError as exc:
            logging.exception(exc)
            
            
class BindCMD(BaseCMD):
    pass


class UDPAssociateCMD(BaseCMD):
    pass


class SocksProtocol:
    
    VERSION = 5
    CMD_HANDLERS = {
        0x01: ConnectCMD,
        0x02: BindCMD,
        0x03: UDPAssociateCMD
    }
    
    def __init__(self, reader, writer, auth_policy):
        self._auth_policy = auth_policy
        self._reader = reader
        self._writer = writer
        self._atyp = None
        
    @property
    def proxy_transport(self):
        if self._writer is not None:
            return self._writer._transport
    
    @property
    def bnd_addr(self):
        if self.proxy_transport is not None:
            return self.proxy_transport.get_extra_info('sockname')[0]
    
    @property
    def bnd_port(self):
        if self.proxy_transport is not None:
            return self.proxy_transport.get_extra_info('sockname')[1]
    
    async def accept_connection(self):
        cli_addr = self.proxy_transport.get_extra_info('peername')
        logging.info('Accepted connection from {}:{}'.format(*cli_addr))
        try:
            await self.authorize()
            await self.handle_client()
        except ProxyError as exc:
            if exc.REPLY is not None:
                await self.send_reply(exc.REPLY)
            logging.exception(exc)
        except Exception as exc:
            logging.exception(exc)
        self._writer.close()
    
    async def authorize(self):
        version, nmethods = struct.unpack('!BB', await self._reader.read(2))
        cli_auth = struct.unpack(
            'B' * nmethods, await self._reader.read(nmethods)
        )
        if self._auth_policy.METHOD not in cli_auth:
            raise UnsupportedAuthorizationType
        return await self._auth_policy.negotiate(self._reader, self._writer)
        
    async def handle_client(self):
        cli_request = await self._reader.read(4)
        version, cmd, rsv, self._atyp = struct.unpack('!BBBB', cli_request)
        try:
            cmd_handler = self.CMD_HANDLERS[cmd](self._reader, self._writer)
        except KeyError:
            raise UnsupportedCMD
        await self.send_reply(SocksReply.SUCCESS)
        return await cmd_handler.serve()
        
    async def send_reply(self, reply):
        self._writer.write(
            struct.pack('!BBBB', SOCKS_VERSION, reply, 0, self._atyp)
        )
        self._writer.write(socket.inet_aton(self.bnd_addr))
        self._writer.write(struct.pack('!H', self.bnd_port))


async def accept_connection(reader, writer, auth_policy=None):
    auth_policy = auth_policy if auth_policy is not None else WithoutAuth()
    protocol = SocksProtocol(reader, writer, auth_policy)
    await protocol.accept_connection()
    

async def create_server(host, port, auth_policy=None):
    await asyncio.start_server(
        functools.partial(accept_connection, auth_policy=auth_policy),
        host, port
    )
