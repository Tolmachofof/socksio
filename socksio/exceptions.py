from .common import SocksReply


class ProxyError(Exception):
    
    REPLY = SocksReply.GENERAL_SOCKS_SERVER_FAILURE


class UnsupportedCMD(ProxyError):
    
    REPLY = SocksReply.COMMAND_NOT_SUPPORTED


class AuthorizationError(ProxyError):
    
    REPLY = None
    
    
class UnsupportedAuthorizationType(AuthorizationError):
    pass
