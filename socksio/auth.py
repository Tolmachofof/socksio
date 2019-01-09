import struct

from .common import SOCKS_VERSION, SocksReply


class BaseAuthentication:

    async def negotiate(self, reader, writer):
        await self.authenticate(reader, writer)
        self.on_success(writer)
    
    async def authenticate(self, reader, writer):
        raise NotImplementedError

    def on_success(self, writer):
        writer.write(struct.pack(
            '!BB', SOCKS_VERSION, SocksReply.SUCCESS)
        )


class WithoutAuth(BaseAuthentication):

    METHOD = 0x00

    async def authenticate(self, reader, writer):
        pass
