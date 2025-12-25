class SibnaError(Exception):
    """Base exception for Sibna Protocol."""
    pass

class ProtocolError(SibnaError):
    """Protocol-level violations (encryption, handshake)."""
    pass

class NetworkError(SibnaError):
    """Connection or server issues."""
    pass

class AuthError(SibnaError):
    """Authentication or Identity failures."""
    pass
