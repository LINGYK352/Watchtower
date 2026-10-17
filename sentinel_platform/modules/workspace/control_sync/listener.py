"""Opt-in Windows peer gateway; the desktop UI and login API remain loopback-only."""
from __future__ import annotations

import platform
import socket
import threading

from .security import ControlSyncError


class PeerListener:
    def __init__(self, repo):
        self.settings = repo.collection("control_sync_listener")
        self.settings.update_one({"_id": "default"}, {"$setOnInsert": {"enabled": False, "port": 5588}}, upsert=True)
        self.available = platform.system().lower() == "windows"
        self.app = None
        self.server = None
        self.lock = threading.RLock()
        self.error = ""

    def attach(self, app):
        with self.lock:
            self.app = app
            if self.available and self.settings.find_one({"_id": "default"}).get("enabled"):
                try:
                    self._start()
                except ControlSyncError as exc:
                    self.error = str(exc)

    def public(self):
        settings = self.settings.find_one({"_id": "default"}) or {}
        addresses = ["127.0.0.1"]
        if self.available:
            try:
                addresses += [a[4][0] for a in socket.getaddrinfo(socket.gethostname(), None, family=socket.AF_INET, type=socket.SOCK_STREAM) if a[4][0] != "127.0.0.1"]
            except OSError:
                pass
        from .firewall_status import status
        firewall=status(settings.get('port',5588)) if self.available and self.server is not None else {'state':'inactive'}
        return {"firewall":firewall,"available": self.available, "enabled": bool(settings.get("enabled")), "port": settings.get("port", 5588),
                "running": self.server is not None, "error": self.error,
                "targets": [f"http://{ip}:{settings.get('port', 5588)}" for ip in sorted(set(addresses))]}

    def require_pairing_ready(self, body):
        if self.available and body.get("node") is None:
            state = self.public()
            if not state["enabled"] or not state["running"]:
                raise ControlSyncError("Windows同步接收端口尚未启用或启动失败，请先启用接收端口；也可让Windows主动连接VM并选择拉取 / Windows receiver is not running. Enable it first, or connect from Windows and pull the VM data", 409)

    def configure(self, body):
        if not self.available or self.app is None:
            raise ControlSyncError("Web端使用现有服务端口 / Web uses its existing service port")
        enabled, port = body.get("enabled"), body.get("port")
        if not isinstance(enabled, bool) or isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
            raise ControlSyncError("监听开关或端口无效 / Invalid listener setting")
        with self.lock:
            old = self.settings.find_one({"_id": "default"})
            self._stop()
            self.settings.update_one({"_id": "default"}, {"$set": {"enabled": enabled, "port": port}})
            try:
                if enabled:
                    self._start()
                self.error = ""
            except ControlSyncError:
                self.settings.replace_one({"_id": "default"}, old)
                if old.get("enabled"):
                    self._start()
                raise
        return self.public()

    def _start(self):
        if self.server is not None:
            return
        settings = self.settings.find_one({"_id": "default"})
        def peer_only(environ, start_response):
            path = environ.get("PATH_INFO", "")
            if not path.startswith(("/api/control_sync/peer/", "/api/collaboration/peer/")) or environ.get("REQUEST_METHOD") != "POST":
                raw = b'{"error":"Peer transport only"}'
                start_response("404 Not Found", [("Content-Type", "application/json"), ("Content-Length", str(len(raw)))])
                return [raw]
            return self.app(environ, start_response)
        try:
            # Reuse the already shipped native HTTP runtime; no installer dependency.
            from waitress import create_server
            server = create_server(peer_only, host="0.0.0.0", port=settings["port"], threads=4,
                                   connection_limit=32, channel_timeout=30, max_request_body_size=8 * 1024 * 1024,
                                   clear_untrusted_proxy_headers=True)
        except OSError:
            raise ControlSyncError("同步接收端口无法绑定，请选择其他端口 / Cannot bind sync receiver port; choose another port", 409) from None
        self.server = server
        threading.Thread(target=server.run, daemon=True, name="watchtower-peer-listener").start()

    def _stop(self):
        if self.server:
            from waitress.wasyncore import close_all
            self.server.task_dispatcher.shutdown(cancel_pending=True, timeout=2)
            close_all(map=self.server._map)
            self.server = None
