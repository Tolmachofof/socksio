import struct


class AuthenticationError(Exception):
    pass


class BaseAuthentication:

    SUCCESS = 0x00
    FAIL = 0x01

    def __init__(self, protocol_version):
        self._protocol_version = protocol_version

    async def negotiate(self, reader, writer):
        raise NotImplementedError

    def on_success(self, writer):
        writer.write(struct.pack('!BB', self._protocol_version, self.SUCCESS))

    def on_fail(self, writer):
        writer.write(struct.pack('!BB', self._protocol_version, self.FAIL))


class WithoutAuth(BaseAuthentication):

    METHOD = 0x00

    async def negotiate(self, reader, writer):
        self.on_success(writer)


class UsernamePassword(BaseAuthentication):

    METHOD = 0x01

    def __init__(self, protocol_version, auth_backend):
        super().__init__(protocol_version)
        self._auth_backend = auth_backend

    async def negotiate(self, reader, writer):
        username, password = await self.get_credentials(reader)
        if await self._auth_backend.verify_credentials(username, password):
            self.on_success(writer)
        else:
            self.on_fail(writer)
            raise AuthenticationError

    async def get_credentials(self, reader):
        """Read client data and return username/password

        +----+------+----------+------+----------+
        |VER | ULEN |  UNAME   | PLEN |  PASSWD  |
        +----+------+----------+------+----------+
        | 1  |  1   | 1 to 255 |  1   | 1 to 255 |
        +----+------+----------+------+----------+

        :param reader: the client stream reader.
        :return:
        """
        ver, ulen = struct.unpack('!BB', await reader.read(2))
        username = struct.unpack('!{}s'.format(ulen), await reader.read(ulen))
        plen = struct.unpack('!B', await reader.read(1))
        password = struct.unpack('!{}s'.format(plen), await reader.read(plen))
        return username, password

