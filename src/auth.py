"""OCI 统一认证管理：支持 Session Token、API Key、Instance Principals 与浏览器登录。"""

from __future__ import annotations

import base64
import ctypes
import json
import os
import time
import urllib.parse
import webbrowser
from ctypes import wintypes
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from threading import Thread
from typing import Any, Dict, Optional, Tuple

import jwt
import oci
import requests
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey

# ==================== 凭据加解密与存储 ====================


class _DataBlob(ctypes.Structure):
    _fields_ = [("size", wintypes.DWORD), ("data", ctypes.POINTER(ctypes.c_ubyte))]


def _dpapi(data: bytes, decrypt: bool = False) -> bytes:
    """Windows 平台使用 DPAPI 加密凭据，其他平台直接返回。"""
    if os.name != "nt":
        return data
    crypt32, kernel32 = ctypes.WinDLL("crypt32"), ctypes.WinDLL("kernel32")
    fn = crypt32.CryptUnprotectData if decrypt else crypt32.CryptProtectData
    fn.argtypes = [
        ctypes.POINTER(_DataBlob),
        ctypes.c_void_p,
        ctypes.POINTER(_DataBlob),
        ctypes.c_void_p,
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.POINTER(_DataBlob),
    ]
    fn.restype = wintypes.BOOL
    kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    kernel32.LocalFree.restype = ctypes.c_void_p

    buf = ctypes.create_string_buffer(data)
    src = _DataBlob(len(data), ctypes.cast(buf, ctypes.POINTER(ctypes.c_ubyte)))
    dst = _DataBlob()
    if not fn(ctypes.byref(src), None, None, None, None, 1, ctypes.byref(dst)):
        raise RuntimeError("Windows DPAPI 凭据加解密失败")
    try:
        return ctypes.string_at(dst.data, dst.size)
    finally:
        kernel32.LocalFree(dst.data)


class SessionStore:
    """管理本地 Session Token 缓存文件 (~/.oci/python-client/<profile>/session.bin)。"""

    def __init__(self, profile: str = "ORACLE") -> None:
        self.profile = profile
        self.dir = Path.home() / ".oci" / "python-client" / profile
        self.path = self.dir / "session.bin"

    def save(self, data: Dict[str, str]) -> None:
        self.dir.mkdir(parents=True, exist_ok=True)
        raw = json.dumps(data).encode("utf-8")
        self.path.write_bytes(_dpapi(raw, decrypt=False))

    def load(self) -> Optional[Dict[str, str]]:
        if not self.path.exists():
            return None
        try:
            raw_bytes = self.path.read_bytes()
            if raw_bytes.startswith(b"OCIPY1D\x00"):
                raw_bytes = raw_bytes[8:]
            raw = _dpapi(raw_bytes, decrypt=True)
            return json.loads(raw.decode("utf-8"))
        except Exception:
            return None


# ==================== 密钥与 Token 辅助 ====================


def _read_key(pem: bytes, password: Optional[str] = None) -> RSAPrivateKey:
    key = serialization.load_pem_private_key(
        pem, password=password.encode() if password else None
    )
    if not isinstance(key, RSAPrivateKey):
        raise ValueError("OCI 需要 RSA 格式私钥")
    return key


def _parse_token(token: str) -> Tuple[int, str]:
    """解析 token 取得到期时间戳与租户 OCID。"""
    claims = jwt.decode(token, options={"verify_signature": False})
    exp = int(claims.get("exp", 0))
    tenant = claims.get("res_tenant") or claims.get("tenant") or ""
    return exp, tenant


# ==================== 浏览器 SSO 登录 ====================


class _LoginHandler(BaseHTTPRequestHandler):
    token: Optional[str] = None

    def do_GET(self) -> None:  # noqa: N802
        query = urllib.parse.urlparse(self.path).query
        params = urllib.parse.parse_qs(query)
        if "token" in params:
            _LoginHandler.token = params["token"][0]
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            body = "<h2>Oracle 登录成功，可以关闭此窗口。</h2>".encode("utf-8")
            self.wfile.write(body)
        else:
            self.send_response(400)
            self.end_headers()

    def log_message(self, *args: Any) -> None:
        pass


def _browser_login(
    region: str, tenant_name: Optional[str] = None, timeout: int = 180
) -> Tuple[str, RSAPrivateKey]:
    """生成 RSA 密钥对并启动本地 8181 端口监听，唤起浏览器完成登录。"""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pub_der = key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.PKCS1
    )
    pub_b64 = base64.urlsafe_b64encode(pub_der).decode().rstrip("=")

    _LoginHandler.token = None
    server = HTTPServer(("127.0.0.1", 8181), _LoginHandler)
    server.timeout = timeout
    thread = Thread(target=server.handle_request, daemon=True)
    thread.start()

    params = {
        "action": "login",
        "client_id": "iaas.oci.oraclecloud.com",
        "response_type": "token",
        "public_key": pub_b64,
    }
    if tenant_name:
        params["tenant"] = tenant_name
    endpoint = oci.regions.endpoint_for("auth", region)
    url = f"{endpoint}/v1/oauth2/token?{urllib.parse.urlencode(params)}"
    webbrowser.open(url)

    thread.join(timeout=timeout)
    server.server_close()

    if not _LoginHandler.token:
        raise TimeoutError("浏览器登录超时或未接收到 Token。")
    return _LoginHandler.token, key


# ==================== 统一认证中心 ====================


class AuthManager:
    """管理 OCI 多种认证方式的推断、刷新与登录。"""

    def __init__(
        self,
        profile: str = "DEFAULT",
        region: Optional[str] = None,
        config_file: Optional[Path] = None,
        user: Optional[str] = None,
        fingerprint: Optional[str] = None,
        tenancy: Optional[str] = None,
        key_file: Optional[str] = None,
        key_content: Optional[str] = None,
        pass_phrase: Optional[str] = None,
        use_instance_principals: bool = False,
    ) -> None:
        self.profile = profile
        self.region = region
        self.config_file = config_file or (Path.home() / ".oci" / "config")
        self.store = SessionStore(profile)

        self._user = user or os.environ.get("OCI_USER")
        self._fingerprint = fingerprint or os.environ.get("OCI_FINGERPRINT")
        self._tenancy = tenancy or os.environ.get("OCI_TENANCY")
        self._key_file = key_file or os.environ.get("OCI_KEY_FILE")
        self._key_content = key_content or os.environ.get("OCI_KEY_CONTENT")
        self._pass_phrase = pass_phrase or os.environ.get("OCI_KEY_PASSPHRASE")
        self._use_instance_principals = use_instance_principals

    def get_auth(self) -> Tuple[Any, Dict[str, str], str]:
        """返回 (signer, config_dict, tenancy_ocid)。"""
        # 1. 实例主体
        if self._use_instance_principals:
            signer = oci.auth.signers.InstancePrincipalsSecurityTokenSigner()
            reg = self.region or getattr(signer, "region", "us-sanjose-1")
            return signer, {"region": reg}, getattr(signer, "tenancy_id", "")

        # 2. 显式参数 API Key
        if self._user and self._fingerprint and self._tenancy:
            signer = oci.signer.Signer(
                tenancy=self._tenancy,
                user=self._user,
                fingerprint=self._fingerprint,
                private_key_file_location=self._key_file,
                private_key_content=self._key_content,
                pass_phrase=self._pass_phrase,
            )
            reg = self.region or "us-sanjose-1"
            config_dict = {
                "region": reg,
                "tenancy": self._tenancy,
                "user": self._user,
                "fingerprint": self._fingerprint,
                "key_file": self._key_file,
            }
            return signer, config_dict, self._tenancy

        # 3. 本地 DPAPI 缓存的会话 Token
        cached = self.store.load()
        if cached:
            exp, tenant = _parse_token(cached["token"])
            if exp > time.time():
                key = _read_key(cached["private_key"].encode())
                signer = oci.auth.signers.SecurityTokenSigner(cached["token"], key)
                signer.token = cached["token"]
                reg = self.region or cached.get("region", "us-sanjose-1")
                if exp - time.time() <= 300:
                    try:
                        signer, reg, tenant = self._refresh_token(
                            cached["token"], key, reg, tenant
                        )
                    except Exception:
                        pass
                return signer, {"region": reg, "tenancy": tenant}, tenant

        # 4. ~/.oci/config 配置文件（支持自动回退 DEFAULT 与 ORACLE）
        if self.config_file.exists():
            cfg = None
            for p in (self.profile, "DEFAULT", "ORACLE"):
                if not p:
                    continue
                try:
                    cfg = oci.config.from_file(str(self.config_file), p)
                    self.profile = p
                    break
                except Exception:
                    pass
            if cfg is None:
                raise RuntimeError(
                    f"在配置文件 {self.config_file} 中未找到可用 profile"
                )

            reg = self.region or cfg.get("region", "us-sanjose-1")
            tenant = cfg["tenancy"]

            if "security_token_file" in cfg:
                tok = (
                    Path(cfg["security_token_file"])
                    .expanduser()
                    .read_text(encoding="utf-8")
                    .strip()
                )
                k_bytes = Path(cfg["key_file"]).expanduser().read_bytes()
                key = _read_key(k_bytes, cfg.get("pass_phrase"))
                signer = oci.auth.signers.SecurityTokenSigner(tok, key)
                signer.token = tok
                return (
                    signer,
                    {"region": reg, "tenancy": tenant},
                    tenant,
                )

            if "user" in cfg:
                signer = oci.signer.Signer(
                    tenancy=tenant,
                    user=cfg["user"],
                    fingerprint=cfg["fingerprint"],
                    private_key_file_location=cfg.get("key_file"),
                    pass_phrase=cfg.get("pass_phrase"),
                    private_key_content=cfg.get("key_content"),
                )
                return signer, dict(cfg), tenant

        raise RuntimeError(
            "未找到可用 OCI 认证凭据，请运行 auth login 或配置 ~/.oci/config"
        )

    def _refresh_token(
        self, old_token: str, key: RSAPrivateKey, region: str, tenancy: str
    ) -> Tuple[oci.auth.signers.SecurityTokenSigner, str, str]:
        signer = oci.auth.signers.SecurityTokenSigner(old_token, key)
        url = f"{oci.regions.endpoint_for('auth', region)}/v1/authentication/refresh"
        resp = requests.post(
            url, json={"currentToken": old_token}, auth=signer, timeout=30
        )
        if resp.status_code != 200:
            raise RuntimeError(f"刷新 Token 失败 (HTTP {resp.status_code})")
        new_tok = resp.json()["token"]
        pem = key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ).decode()
        self.store.save(
            {
                "region": region,
                "tenancy": tenancy,
                "token": new_tok,
                "private_key": pem,
            }
        )
        s = oci.auth.signers.SecurityTokenSigner(new_tok, key)
        s.token = new_tok
        return s, region, tenancy

    def login(
        self, tenant_name: Optional[str] = None, timeout: int = 180
    ) -> Dict[str, Any]:
        """唤起浏览器完成登录并刷新保存凭据。"""
        reg = self.region or "us-sanjose-1"
        token, key = _browser_login(reg, tenant_name, timeout)
        exp, tenant = _parse_token(token)
        _, reg, tenant = self._refresh_token(token, key, reg, tenant)
        return {"status": "ok", "region": reg, "tenancy": tenant}

    def refresh(self) -> Dict[str, Any]:
        """手动刷新已存会话。"""
        cached = self.store.load()
        if not cached:
            raise RuntimeError("未找到本地会话凭据，请先执行 login")
        key = _read_key(cached["private_key"].encode())
        _, reg, tenant = self._refresh_token(
            cached["token"], key, cached["region"], cached["tenancy"]
        )
        return {"status": "refreshed", "region": reg, "tenancy": tenant}

    def status(self, online: bool = False) -> Dict[str, Any]:
        """查询当前认证有效性与剩余有效时长。"""
        # 1. 优先展示本地会话缓存（包含已过期情况）
        cached = self.store.load()
        if cached:
            exp, tenant = _parse_token(cached["token"])
            rem = max(0, int(exp - time.time()))
            info = {
                "profile": self.profile,
                "region": cached.get("region") or self.region or "us-sanjose-1",
                "tenancy": tenant,
                "auth_type": "SecurityTokenSigner",
                "valid": rem > 0,
                "remaining_seconds": rem,
                "expires_at": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(exp)),
            }
            if not info["valid"]:
                info["message"] = (
                    "会话已过期，请运行 python src/cli.py auth login 重新登录"
                )
            return info

        # 2. 无本地缓存时尝试通过配置或参数推断
        try:
            signer, cfg, tenant = self.get_auth()
            info = {
                "profile": self.profile,
                "region": cfg.get("region"),
                "tenancy": tenant,
                "auth_type": type(signer).__name__,
                "valid": True,
            }
            tok = getattr(signer, "token", None)
            if tok:
                exp, _ = _parse_token(tok)
                rem = max(0, int(exp - time.time()))
                info["remaining_seconds"] = rem
                info["expires_at"] = time.strftime(
                    "%Y-%m-%d %H:%M:%S", time.localtime(exp)
                )
                info["valid"] = rem > 0
            if online:
                client = oci.identity.IdentityClient(cfg, signer=signer)
                client.get_tenancy(tenant)
                info["online_verified"] = True
            return info
        except Exception as e:
            return {"profile": self.profile, "valid": False, "error": str(e)}
