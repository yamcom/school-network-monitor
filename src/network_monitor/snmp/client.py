"""Robust SNMP Client supporting SNMPv3 (AuthPriv) and SNMPv2c."""

from __future__ import annotations

import asyncio
import logging
import sys
import warnings

# 1. 消除明文社群字串的安全性警告 (PySnmpWeakCryptoWarning)
warnings.filterwarnings("ignore", category=UserWarning, module="pysnmp")

# 2. 針對 Windows 平台切換 Event Loop Policy，修復 ProactorDatagramTransport closed 錯誤
if sys.platform == "win32":
    try:
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    except Exception:
        pass

import pysnmp.hlapi.asyncio as hlapi

# 3. 修補 Windows 繁體中文 (cp950) 讀取 pysnmp 內建 MIB 產生的 UnicodeDecodeError
try:
    from pysnmp.smi import builder
    if hasattr(builder, "DirMibSource"):
        _orig_dir_get_data = builder.DirMibSource._getData
        def _patched_dir_get_data(self, f, mode="r"):
            if "b" not in mode:
                import os
                p = os.path.join(self._srcName, f)
                if os.path.exists(p):
                    with open(p, mode, encoding="utf-8", errors="replace") as fp:
                        return fp.read(), p
            return _orig_dir_get_data(self, f, mode)
        builder.DirMibSource._getData = _patched_dir_get_data
except Exception:
    pass

# 4. 優先採用新版蛇形命名，相容舊版駝峰命名
if hasattr(hlapi, "get_cmd"):
    getCmdFunc = hlapi.get_cmd
else:
    getCmdFunc = getattr(hlapi, "getCmd", None)

if hasattr(hlapi, "walk_cmd"):
    walkCmdFunc = hlapi.walk_cmd
else:
    walkCmdFunc = getattr(hlapi, "walkCmd", None)

# 5. 處理 DES / AES 協定在新舊版本中的命名差異
DES_PROTO = getattr(
    hlapi,
    "usmDesCbcProtocol",
    getattr(hlapi, "usmDESPrivProtocol", getattr(hlapi, "usmDESProtocol", None)),
)
AES_PROTO = getattr(hlapi, "usmAesCfb128Protocol", None)
SHA_PROTO = getattr(hlapi, "usmHMACSHAAuthProtocol", None)
MD5_PROTO = getattr(hlapi, "usmHMACMD5AuthProtocol", None)
NO_AUTH = getattr(hlapi, "usmNoAuthProtocol", None)
NO_PRIV = getattr(hlapi, "usmNoPrivProtocol", None)

logger = logging.getLogger("network_monitor.snmp.client")


class SNMPClient:
    def __init__(
        self,
        ip: str,
        version: str = "3",
        timeout: float = 3.0,
        retries: int = 1,
        port: int = 161,
        community: Optional[str] = None,
        v3_user: Optional[str] = None,
        v3_auth_key: Optional[str] = None,
        v3_auth_proto: str = "SHA",
        v3_priv_key: Optional[str] = None,
        v3_priv_proto: str = "AES",
    ):
        self.ip = ip
        self.version = str(version)
        self.timeout = timeout
        self.retries = retries
        self.port = port
        self.community = community or "public"
        self.v3_user = v3_user or ""
        self.v3_auth_key = v3_auth_key
        self.v3_auth_proto = v3_auth_proto.upper()
        self.v3_priv_key = v3_priv_key
        self.v3_priv_proto = v3_priv_proto.upper()

    def _get_auth_data(self) -> Any:
        if self.version in ("2c", "2"):
            return hlapi.CommunityData(self.community, mpModel=1)

        auth_protocol = NO_AUTH
        if self.v3_auth_key:
            auth_protocol = SHA_PROTO if self.v3_auth_proto == "SHA" else MD5_PROTO

        priv_protocol = NO_PRIV
        if self.v3_priv_key:
            priv_protocol = AES_PROTO if self.v3_priv_proto == "AES" else DES_PROTO

        return hlapi.UsmUserData(
            userName=self.v3_user,
            authKey=self.v3_auth_key,
            authProtocol=auth_protocol,
            privKey=self.v3_priv_key,
            privProtocol=priv_protocol,
        )

    async def _get_target(self) -> Any:
        if hasattr(hlapi.UdpTransportTarget, "create"):
            res = hlapi.UdpTransportTarget.create(
                (self.ip, self.port), timeout=self.timeout, retries=self.retries
            )
            if asyncio.iscoroutine(res):
                return await res
            return res
        return hlapi.UdpTransportTarget(
            (self.ip, self.port), timeout=self.timeout, retries=self.retries
        )

    async def get(self, oid: str, engine: Optional[hlapi.SnmpEngine] = None) -> Optional[str]:
        snmp_engine = engine or hlapi.SnmpEngine()
        auth = self._get_auth_data()
        target = await self._get_target()

        errorIndication, errorStatus, errorIndex, varBinds = await getCmdFunc(
            snmp_engine,
            auth,
            target,
            hlapi.ContextData(),
            hlapi.ObjectType(hlapi.ObjectIdentity(oid)),
        )

        if errorIndication:
            logger.warning(f"SNMP GET {self.ip}:{oid} ErrorIndication: {errorIndication}")
            return None
        if errorStatus:
            logger.warning(f"SNMP GET {self.ip}:{oid} ErrorStatus: {errorStatus.prettyPrint()}")
            return None

        for varBind in varBinds:
            return str(varBind[1])
        return None

    async def walk(self, root_oid: str, engine: Optional[hlapi.SnmpEngine] = None) -> List[Tuple[str, Any]]:
        snmp_engine = engine or hlapi.SnmpEngine()
        auth = self._get_auth_data()
        target = await self._get_target()
        results: List[Tuple[str, Any]] = []

        norm_root = root_oid.strip(".")
        last_oid = None

        async for errorIndication, errorStatus, errorIndex, varBinds in walkCmdFunc(
            snmp_engine,
            auth,
            target,
            hlapi.ContextData(),
            hlapi.ObjectType(hlapi.ObjectIdentity(root_oid)),
            lexicographicMode=False,
        ):
            if errorIndication or errorStatus:
                break

            should_stop = False
            for varBind in varBinds:
                curr_oid = str(varBind[0]).strip(".")

                # 防死迴圈保護
                if curr_oid == last_oid:
                    should_stop = True
                    break
                last_oid = curr_oid

                # 防越界保護 (超出子樹即停止)
                if not curr_oid.startswith(norm_root):
                    should_stop = True
                    break

                results.append((str(varBind[0]), varBind[1]))

            if should_stop:
                break

        return results

    def _run_in_loop(self, coro):
        try:
            loop = asyncio.get_event_loop()
            if loop.is_closed():
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)

        return loop.run_until_complete(coro)

    def sync_get(self, oid: str) -> Optional[str]:
        return self._run_in_loop(self.get(oid))

    def sync_walk(self, root_oid: str) -> List[Tuple[str, Any]]:
        return self._run_in_loop(self.walk(root_oid))