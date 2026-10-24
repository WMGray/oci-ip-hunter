"""OCI 官方 Python SDK 封装套件（纯 SDK 实现，无 CLI 依赖）。"""

try:
    from auth import AuthManager
    from client import OCIClient
except ImportError:
    from src.auth import AuthManager
    from src.client import OCIClient

__all__ = ["OCIClient", "AuthManager"]
