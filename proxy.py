#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
proxy.py —— PDF 图表转矢量页面的本地 CORS 代理（零依赖，仅用 Python 标准库）

作用：
  浏览器直连内网 OpenAI 兼容网关时，常因网关不回 CORS 头 / OPTIONS 预检被鉴权拦截
  而报 "Failed to fetch"。本脚本在 127.0.0.1 上起一个转发服务：
    * 把请求原样转发给你指定的上游（保留 Authorization 等头）；
    * 对所有响应（含 4xx/5xx）无条件补 CORS 头；
    * OPTIONS 预检直接回 204，不送到上游；
    * 端口被占用时自动顺延（8787 → 8788 … 最多 10 个）。

用法：
  python proxy.py --upstream http://10.17.121.224:3425
  python proxy.py --upstream http://10.17.121.224:3425 --port 8787
  PFV_UPSTREAM=http://10.17.121.224:3425 python proxy.py

Windows 用户可直接双击同目录的 start-proxy.bat，它会先切到 UTF-8 代码页再调用本脚本，
所以这里的英文兜底提示与中文提示都不会乱码。
"""

import argparse
import http.client
import json
import os
import socket
import sys
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HOP_BY_HOP = {
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailers", "transfer-encoding", "upgrade", "content-length",
}

CORS_HEADERS = {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, POST, PUT, PATCH, DELETE, HEAD, OPTIONS",
    "Access-Control-Allow-Headers": "Authorization, Content-Type, Accept, X-Api-Key, *",
    "Access-Control-Expose-Headers": "*",
    "Access-Control-Max-Age": "86400",
}

UPSTREAM = None
TIMEOUT = 180
CONNECT_TIMEOUT = 10

PORT_SPAN = 10  # 8787 起最多尝试 10 个端口


def classify_connect_error(e):
    """把 TCP 连接阶段的异常翻译成人能看懂的诊断。
    注意：Windows 对无响应主机约 21 秒（SYN 重传 3+6+12s）就放弃，
    所以连接超时通常在 ~21s 触发，与 --timeout（读取超时）无关。"""
    if isinstance(e, (socket.timeout, TimeoutError)):
        return ("连接超时：主机完全无响应（SYN 无应答）。通常是 IP/端口不对、网关宕机、"
                "VPN 没连，或防火墙静默丢包。Windows 系统栈对无响应主机约 21 秒即放弃，")
    if isinstance(e, ConnectionRefusedError):
        return ("连接被拒绝：主机在线，但该端口没有服务在监听。"
                "确认网关进程是否启动、端口是否正确，")
    if isinstance(e, socket.gaierror):
        return ("域名解析失败：检查 --upstream 的主机名拼写与本机 DNS，")
    code = getattr(e, "winerror", None) or getattr(e, "errno", None)
    return ("网络不可达（errno/winerror=%s）：路由、网段或防火墙拦截。" % (code,) +
            "若在校园网/内网请确认 VPN 已连接，")


def probe_upstream(host, port, timeout=3.0):
    """启动时对上游做一次 TCP 探测，提前暴露「网关不可达」。"""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((host, port))
        return True, None
    except Exception as e:
        advice = classify_connect_error(e)
        return False, advice
    finally:
        try:
            s.close()
        except Exception:
            pass


def setup_stdio():
    """让 stdout/stderr 尽量用 UTF-8 输出；重定向/无控制台/老版本 Python 都不报错。"""
    for name in ("stdout", "stderr"):
        stream = getattr(sys, name, None)
        if stream is None:
            continue
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError, OSError):
            pass


def out(msg=""):
    """安全打印到 stdout：流被关闭/替换/None 时静默跳过，绝不因打印而崩溃。"""
    try:
        if sys.stdout is not None:
            sys.stdout.write("%s\n" % msg)
            sys.stdout.flush()
    except Exception:
        pass


def err(msg=""):
    try:
        if sys.stderr is not None:
            sys.stderr.write("%s\n" % msg)
            sys.stderr.flush()
    except Exception:
        pass


def port_in_use(host, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(0.3)
    try:
        return s.connect_ex((host, port)) == 0
    except OSError:
        return False
    finally:
        try:
            s.close()
        except OSError:
            pass


def make_server(host, start_port):
    """从 start_port 开始找一个没人监听、且能真正 bind 的端口。"""
    for port in range(start_port, start_port + PORT_SPAN):
        if port_in_use(host, port):
            continue
        try:
            return ThreadingHTTPServer((host, port), Handler), port
        except OSError:
            continue
    return None, None


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "pfv-cors-proxy/1.0"

    def log_message(self, fmt, *args):
        err("[proxy] %s %s" % (self.address_string(), fmt % args))

    def handle_one_request(self):
        try:
            super().handle_one_request()
        except (ConnectionResetError, ConnectionAbortedError):
            self.close_connection = True

    # ---- CORS 工具 ----
    def _send_cors(self):
        for k, v in CORS_HEADERS.items():
            self.send_header(k, v)

    def _fail(self, code, message):
        body = json.dumps({"error": {"message": message, "type": "proxy_error"}},
                          ensure_ascii=False).encode("utf-8")
        try:
            self.send_response(code)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self._send_cors()
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        except Exception:
            pass

    # ---- 预检 ----
    def do_OPTIONS(self):
        self.send_response(204)
        self._send_cors()
        self.send_header("Content-Length", "0")
        self.end_headers()

    # ---- 转发 ----
    def _forward(self, method):
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = 0
        body = self.rfile.read(length) if length else None

        conn_cls = http.client.HTTPSConnection if UPSTREAM.scheme == "https" else http.client.HTTPConnection
        port = UPSTREAM.port or (443 if UPSTREAM.scheme == "https" else 80)
        # 连接与读取分开计时：连接用较短的 CONNECT_TIMEOUT 快速失败，
        # 连接建立后再把 socket 超时改成 TIMEOUT（模型生成可能很慢）。
        conn = conn_cls(UPSTREAM.hostname, port, timeout=CONNECT_TIMEOUT)
        t0 = time.time()
        path = self.path
        prefix = UPSTREAM.path.rstrip("/")
        if prefix:
            path = prefix + (path if path.startswith("/") else "/" + path)

        headers = {}
        for k, v in self.headers.items():
            lk = k.lower()
            if lk in HOP_BY_HOP or lk in ("host", "origin", "referer"):
                continue
            headers[k] = v
        headers["Host"] = UPSTREAM.netloc
        headers.setdefault("Accept-Encoding", "identity")  # 避免上游压缩，直接透传长度

        try:
            conn.connect()
            if conn.sock is not None:
                conn.sock.settimeout(TIMEOUT)
        except Exception as e:
            waited = time.time() - t0
            advice = classify_connect_error(e)
            err("[proxy] 无法连接上游 %s（%s: %s，%.1fs）" % (UPSTREAM.geturl(), type(e).__name__, e, waited))
            err("[proxy] 诊断：%s建议先在代理所在机器执行：ping %s 或 Test-NetConnection %s -Port %d" %
                (advice, UPSTREAM.hostname, UPSTREAM.hostname, port))
            self._fail(502, "代理无法连接上游 %s —— %s（等了 %.1f 秒）。"
                       "请检查 VPN / 网关地址端口 / 防火墙；可在代理窗口的机器上先 ping %s 验证。" %
                       (UPSTREAM.geturl(), advice, waited, UPSTREAM.hostname))
            return

        try:
            conn.request(method, path, body=body, headers=headers)
            resp = conn.getresponse()
        except (socket.timeout, TimeoutError):
            waited = time.time() - t0
            err("[proxy] 读取上游响应超时（等待响应头）：%s（已等 %.1fs，timeout=%ds）" % (UPSTREAM.geturl(), waited, TIMEOUT))
            self._fail(502, "上游已连接，但 %d 秒内没有返回响应头（读取超时，已等 %.1f 秒）。模型可能仍在生成："
                       "可加大 proxy.py 的 --timeout、开启页面的流式响应，或检查网关自身的超时配置。" %
                       (TIMEOUT, waited))
            return
        except Exception as e:
            waited = time.time() - t0
            err("[proxy] 转发上游失败：%s（%s: %s，已等 %.1fs）" % (UPSTREAM.geturl(), type(e).__name__, e, waited))
            self._fail(502, "代理转发上游失败：%s: %s（已等 %.1f 秒）。" % (type(e).__name__, e, waited))
            return

        ctype = (resp.getheader("Content-Type") or "").lower()
        is_sse = method != "HEAD" and resp.status == 200 and "text/event-stream" in ctype

        if is_sse:
            # SSE 必须边收边发：否则页面在整个生成期间收不到任何字符，
            # 「已收 N 字符」与首 token 计时都会是假的。
            try:
                self.send_response(resp.status, resp.reason or "")
                for k, v in resp.getheaders():
                    lk = k.lower()
                    if lk in HOP_BY_HOP or lk in ("server", "date") or lk.startswith("access-control-"):
                        continue
                    self.send_header(k, v)
                self._send_cors()
                self.send_header("Transfer-Encoding", "chunked")
                self.send_header("Cache-Control", "no-cache")
                self.end_headers()
                self.wfile.flush()
            except Exception as e:
                err("[proxy] 无法开始流式转发：%s" % e)
                self.close_connection = True
                return
            chunks = 0
            total = 0
            first_ms = None
            try:
                while True:
                    piece = resp.read1(2048)
                    if not piece:
                        break
                    if first_ms is None:
                        first_ms = int((time.time() - t0) * 1000)
                    self.wfile.write(("%x\r\n" % len(piece)).encode("ascii") + piece + b"\r\n")
                    self.wfile.flush()
                    chunks += 1
                    total += len(piece)
                self.wfile.write(b"0\r\n\r\n")
                self.wfile.flush()
                err("[proxy] 流式转发 %s %s -> %s（首块 %s，总 %.1fs，%d 块 %d 字节）" %
                    (method, path, resp.status,
                     ("%.1fs" % (first_ms / 1000.0)) if first_ms is not None else "n/a",
                     time.time() - t0, chunks, total))
            except (socket.timeout, TimeoutError):
                err("[proxy] 读取流式响应超时：%s（已转 %d 块，已等 %.1fs，timeout=%ds）" %
                    (UPSTREAM.geturl(), chunks, time.time() - t0, TIMEOUT))
                self.close_connection = True
            except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
                err("[proxy] 客户端已断开（已转 %d 块，%.1fs）" % (chunks, time.time() - t0))
                self.close_connection = True
            except Exception as e:
                err("[proxy] 流式转发中断：%s: %s（已转 %d 块，%.1fs）" % (type(e).__name__, e, chunks, time.time() - t0))
                self.close_connection = True
            finally:
                try:
                    conn.close()
                except Exception:
                    pass
            return

        try:
            data = resp.read()
        except (socket.timeout, TimeoutError):
            waited = time.time() - t0
            err("[proxy] 读取上游响应超时（响应头已到，等待响应体）：%s（已等 %.1fs，timeout=%ds）" % (UPSTREAM.geturl(), waited, TIMEOUT))
            self._fail(502, "上游已连接且已返回响应头，但 %d 秒内没有返回完整响应体（读取超时，已等 %.1f 秒）。"
                       "模型可能仍在生成：可加大 proxy.py 的 --timeout、开启页面的流式响应，或检查网关自身的超时配置。" %
                       (TIMEOUT, waited))
            return
        except Exception as e:
            waited = time.time() - t0
            err("[proxy] 读取上游响应体失败：%s（%s: %s，已等 %.1fs）" % (UPSTREAM.geturl(), type(e).__name__, e, waited))
            self._fail(502, "代理读取上游响应体失败：%s: %s（已等 %.1f 秒）。" % (type(e).__name__, e, waited))
            return

        try:
            conn.close()
        except Exception:
            pass

        err("[proxy] 上游响应 %s %s -> %s（%.1fs）" % (method, path, resp.status, time.time() - t0))

        self.send_response(resp.status, resp.reason or "")
        for k, v in resp.getheaders():
            lk = k.lower()
            if lk in HOP_BY_HOP or lk in ("server", "date") or lk.startswith("access-control-"):
                continue
            self.send_header(k, v)
        self._send_cors()
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        if method != "HEAD":
            try:
                self.wfile.write(data)
            except Exception:
                pass

    def do_GET(self):
        # 页面用来探测「本地代理在不在」的轻量探针：直接回 200，不打到上游，
        # 也不消耗网关的鉴权/限流配额。
        if self.path.split("?")[0].rstrip("/") in ("/__pfv_ping", "/pfv-ping"):
            body = b'{"ok":true,"proxy":"pfv-cors-proxy"}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self._send_cors()
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        self._forward("GET")

    def do_POST(self):
        self._forward("POST")

    def do_PUT(self):
        self._forward("PUT")

    def do_PATCH(self):
        self._forward("PATCH")

    def do_DELETE(self):
        self._forward("DELETE")

    def do_HEAD(self):
        self._forward("HEAD")


def main():
    global UPSTREAM, TIMEOUT, CONNECT_TIMEOUT
    setup_stdio()

    ap = argparse.ArgumentParser(description="PDF 图表转矢量的本地 CORS 代理")
    ap.add_argument("--upstream", default=os.environ.get("PFV_UPSTREAM", ""),
                    help="上游 OpenAI 兼容地址，如 http://10.17.121.224:3425（也可用环境变量 PFV_UPSTREAM）")
    ap.add_argument("--host", default="127.0.0.1", help="监听地址，默认只监听本机 127.0.0.1")
    ap.add_argument("--port", type=int, default=int(os.environ.get("PFV_PORT", "8787")),
                    help="起始监听端口，默认 8787；被占用时自动顺延")
    ap.add_argument("--timeout", type=int, default=int(os.environ.get("PFV_TIMEOUT", "600")),
                    help="读取上游响应的超时秒数，默认 600（也可用环境变量 PFV_TIMEOUT）")
    ap.add_argument("--connect-timeout", type=int, default=int(os.environ.get("PFV_CONNECT_TIMEOUT", "10")),
                    help="与上游建立 TCP 连接的超时秒数，默认 10（快速失败；Windows 系统栈对无响应主机约 21 秒放弃）")
    args = ap.parse_args()

    if not args.upstream:
        ap.error("必须指定 --upstream，例如：python proxy.py --upstream http://10.17.121.224:3425")
    raw = args.upstream if "://" in args.upstream else "http://" + args.upstream
    UPSTREAM = urllib.parse.urlsplit(raw)
    if UPSTREAM.scheme not in ("http", "https") or not UPSTREAM.hostname:
        ap.error("upstream 不合法：%s" % args.upstream)
    TIMEOUT = max(10, args.timeout)
    CONNECT_TIMEOUT = max(3, min(600, args.connect_timeout))

    srv, port = make_server(args.host, args.port)
    if srv is None:
        err("")
        err("[错误] 端口 %d-%d 都被占用，请关闭占用程序后重试。" % (args.port, args.port + PORT_SPAN - 1))
        return 1

    shifted = port != args.port
    upstream_port = UPSTREAM.port or (443 if UPSTREAM.scheme == "https" else 80)
    up_ok, up_advice = probe_upstream(UPSTREAM.hostname, upstream_port)

    out("=" * 60)
    out(" PDF 图表转矢量 - 本地 CORS 代理")
    out("-" * 60)
    out("  上游网关：%s" % UPSTREAM.geturl())
    out("  监听地址：http://%s:%d" % (args.host, port))
    out("  连接超时：%d 秒 / 读取超时：%d 秒（超时返回 502 JSON，日志会区分两类错误）" %
        (CONNECT_TIMEOUT, TIMEOUT))
    if up_ok:
        out("  上游连通性：✓ TCP 可达（启动探测通过）")
    else:
        out("  上游连通性：✗ 当前不可达 —— %s" % up_advice)
        out("              页面请求仍会尝试转发，但大概率 502；请先恢复网络/VPN 再生成。")
    if shifted:
        out("  注意：端口 %d 已被占用，已自动顺延到 %d。" % (args.port, port))
    out("")
    out("  代理已就绪 -> 页面 Base URL 填 http://%s:%d/v1" % (args.host, port))
    out("  停止方式：在这个窗口按 Ctrl+C，或直接关闭窗口")
    out("=" * 60)
    out("")

    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        out("\n已停止。")
    finally:
        try:
            srv.server_close()
        except Exception:
            pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
