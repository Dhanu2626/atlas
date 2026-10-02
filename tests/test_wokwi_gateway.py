"""The Wokwi private gateway preflight (2026-10-01).

The VS Code extension connects to ws://localhost:9011 when the simulator starts, and
nothing started that gateway unless run_sim.py got that far -- so a failed
prerequisite looked like "Failed to connect to the IoT Gateway". scripts/wokwi_gateway.py
makes the start deterministic. These tests use throwaway fake servers on free ports;
they never touch port 9011, the real gateway, or the real ~/.atlas.
"""

from __future__ import annotations

import base64
import hashlib
import re
import socket
import subprocess
import sys
import threading
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
import run_sim  # noqa: E402
import wokwi_gateway as gw  # noqa: E402

TOML = ROOT / "firmware" / "atlas_device" / "wokwi.toml"
GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


# ---------------------------------------------------------------- fake servers

class FakeServer:
    """A loopback TCP server on a free port. mode 'gateway' completes the WebSocket
    handshake only when the Origin matches (as wokwigw does); 'forbid' answers 403;
    'silent' accepts and never answers."""

    def __init__(self, mode: str, port: int = 0):
        self.mode = mode
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", port))
        self.sock.listen(8)
        self.port = self.sock.getsockname()[1]
        self.stop = False
        self.seen: list[str] = []
        self.thread = threading.Thread(target=self._loop, daemon=True)
        self.thread.start()

    def _loop(self):
        self.sock.settimeout(0.2)
        held = []
        while not self.stop:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                continue
            if self.mode == "silent":
                held.append(conn)
                continue
            conn.settimeout(2)
            try:
                request = conn.recv(4096).decode("latin-1")
            except OSError:
                conn.close()
                continue
            self.seen.append(request)
            headers = {l.split(":", 1)[0].lower(): l.split(":", 1)[1].strip()
                       for l in request.split("\r\n")[1:] if ":" in l}
            ok = self.mode == "gateway" and headers.get("origin") == gw.ORIGIN
            if ok:
                accept = base64.b64encode(hashlib.sha1((headers["sec-websocket-key"] + GUID).encode()).digest()).decode()
                reply = ("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                         f"Sec-WebSocket-Accept: {accept}\r\n\r\n")
            else:
                reply = "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n"
            conn.sendall(reply.encode())
            conn.close()
        for c in held:
            c.close()
        self.sock.close()

    def close(self):
        self.stop = True
        self.thread.join(timeout=2)


@pytest.fixture
def fake():
    made = []

    def make(mode):
        s = FakeServer(mode)
        made.append(s)
        return s

    yield make
    for s in made:
        s.close()


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture
def binary(tmp_path):
    exe = tmp_path / "wokwigw.exe"
    exe.write_bytes(b"pretend gateway")
    return exe, hashlib.sha256(b"pretend gateway").hexdigest()


def write_toml(tmp_path, gateway_line: str):
    p = tmp_path / "wokwi.toml"
    p.write_text(f"[wokwi]\nversion = 1\n\n[net]\n{gateway_line}\n", encoding="utf-8")
    return p


# ------------------------------------------------------------- 1. the configured URL

def test_the_shipped_wokwi_toml_names_exactly_the_private_gateway_and_its_port():
    url, port = gw.read_configured_gateway(TOML)
    assert url == "ws://localhost:9011" == gw.GATEWAY_URL
    assert port == 9011 == gw.PORT
    assert len(re.findall(r"^\s*gateway\s*=", TOML.read_text(encoding="utf-8"), re.M)) == 1


@pytest.mark.parametrize("line", [
    'gateway = "wss://gateway.wokwi.com"', 'gateway = "ws://0.0.0.0:9011"',
    'gateway = "ws://192.168.1.140:9011"', 'gateway = "ws://abc123.ngrok.io:9011"',
    'gateway = "https://localhost:9011"', 'gateway = "localhost:9011"',
])
def test_a_public_lan_or_malformed_gateway_is_refused_and_nothing_starts(tmp_path, binary, line):
    exe, digest = binary
    with pytest.raises(gw.GatewayConfigError):
        gw.read_configured_gateway(write_toml(tmp_path, line))

    def never(*a, **k):
        raise AssertionError("the gateway must not be started for a refused configuration")

    result = gw.start_gateway(toml_path=write_toml(tmp_path, line), binary=exe, expected_sha256=digest,
                              run_dir=tmp_path / "run", popen=never)
    assert result.state == gw.CONFIG_ERROR


def test_a_missing_gateway_section_is_an_error_not_a_default(tmp_path):
    p = tmp_path / "wokwi.toml"
    p.write_text("[wokwi]\nversion = 1\n", encoding="utf-8")
    with pytest.raises(gw.GatewayConfigError, match="no \\[net\\] gateway"):
        gw.read_configured_gateway(p)


def test_the_toml_is_never_rewritten(tmp_path, binary, fake):
    exe, digest = binary
    toml = write_toml(tmp_path, 'gateway = "ws://localhost:9011"')
    before = toml.read_bytes()
    gw.start_gateway(toml_path=toml, binary=exe, expected_sha256="0" * 64, run_dir=tmp_path / "run")
    assert toml.read_bytes() == before


# ------------------------------------------------------------- 2. the binary

def test_a_missing_binary_is_detected_with_where_to_get_it(tmp_path):
    result = gw.verify_binary(tmp_path / "nope.exe")
    assert result.state == gw.MISSING and "github.com/wokwi/wokwigw/releases" in result.message
    assert gw.verify_binary(None).state == gw.MISSING


def test_a_different_binary_is_refused_not_run(tmp_path, binary):
    exe, _ = binary
    called = []
    result = gw.start_gateway(toml_path=TOML, binary=exe, expected_sha256="1" * 64, run_dir=tmp_path / "run",
                              popen=lambda *a, **k: called.append(a))
    assert result.state == gw.HASH_MISMATCH and called == []
    assert "Refusing to run it" in result.message


def test_the_pinned_hash_is_the_official_release_and_the_installed_gateway_matches_it_when_present():
    assert re.fullmatch(r"[0-9a-f]{64}", gw.EXPECTED_SHA256)
    assert gw.EXPECTED_VERSION == "v2.0.1"
    installed = gw.DEFAULT_BINARY
    if installed.is_file():
        assert gw.sha256_file(installed) == gw.EXPECTED_SHA256


# ------------------------------------------------------------- 3. the port

def test_a_free_port_reads_as_stopped(binary):
    exe, _ = binary
    assert gw.port_state(exe, free_port()).state == gw.STOPPED


def test_a_real_handshake_needs_the_origin_and_a_correct_accept(fake):
    server = fake("gateway")
    assert gw.ws_handshake(server.port) == "gateway"
    assert f"Origin: {gw.ORIGIN}" in server.seen[0]
    assert gw.ws_handshake(server.port, origin="https://evil.example").startswith("not_gateway: HTTP/1.1 403")


def test_an_occupied_port_is_reported_by_owner_and_left_alone(binary, fake):
    exe, _ = binary
    other = fake("forbid")                                    # something that is not a gateway
    state = gw.port_state(exe, other.port, owner=lambda p: (4242, Path("C:/Windows/notepad.exe")))
    assert state.state == gw.OCCUPIED and state.pid == 4242
    assert "notepad.exe" in state.message and "left alone" in state.message


def test_a_listener_that_never_answers_is_not_a_gateway(binary, fake):
    exe, _ = binary
    silent = fake("silent")
    assert gw.ws_handshake(silent.port, timeout=0.5) == "no_answer"
    state = gw.port_state(exe, silent.port, owner=lambda p: (7, None),
                          handshake=lambda port, host: gw.ws_handshake(port, host, timeout=0.5))
    assert state.state == gw.OCCUPIED


def test_a_gateway_from_another_binary_is_not_adopted(binary, fake, tmp_path):
    exe, _ = binary
    server = fake("gateway")
    state = gw.port_state(exe, server.port, owner=lambda p: (99, tmp_path / "other.exe"))
    assert state.state == gw.UNVERIFIED and "cannot be verified" in state.message
    unknown = gw.port_state(exe, server.port, owner=lambda p: None)
    assert unknown.state == gw.UNVERIFIED


def test_the_verified_gateway_already_running_is_reused_never_duplicated(binary, fake, tmp_path):
    exe, digest = binary
    server = fake("gateway")

    def never(*a, **k):
        raise AssertionError("a second gateway must not be started")

    result = gw.start_gateway(toml_path=TOML, binary=exe, expected_sha256=digest, run_dir=tmp_path / "run",
                              port=server.port, popen=never, owner=lambda p: (1234, exe))
    assert result.state == gw.ALREADY_RUNNING and result.pid == 1234 and result.ok


# ------------------------------------------------------------- 4. starting it

class FakeProc:
    def __init__(self, listen_port=None, dies_with=None):
        self.pid, self.returncode, self.killed = 777, dies_with, False
        self.server = None

    def poll(self):
        return self.returncode

    def kill(self):
        self.killed = True


def test_start_waits_for_the_port_then_confirms_the_handshake(binary, tmp_path):
    exe, digest = binary
    port = free_port()
    proc, servers = FakeProc(), []

    def popen(argv, **kw):                         # the gateway 'begins listening' once started
        assert argv == [str(exe)]
        servers.append(FakeServer("gateway", port))
        return proc

    try:
        result = gw.start_gateway(toml_path=TOML, binary=exe, expected_sha256=digest, run_dir=tmp_path / "run",
                                  port=port, popen=popen, timeout=3, owner=lambda p: None)
    finally:
        for server in servers:
            server.close()
    assert result.state == gw.READY and result.ok and result.pid == 777
    assert result.process is proc and not proc.killed and "handshake verified" in result.message


def test_a_listener_that_opens_but_fails_the_handshake_is_stopped(binary, tmp_path):
    exe, digest = binary
    port = free_port()
    proc, servers = FakeProc(), []

    def popen(argv, **kw):
        servers.append(FakeServer("forbid", port))
        return proc

    try:
        result = gw.start_gateway(toml_path=TOML, binary=exe, expected_sha256=digest, run_dir=tmp_path / "run",
                                  port=port, popen=popen, timeout=3, owner=lambda p: None)
    finally:
        for server in servers:
            server.close()
    assert result.state == gw.UNAVAILABLE and proc.killed and "handshake failed" in result.message


def test_a_gateway_that_exits_at_once_is_reported_with_its_exit_code(binary, tmp_path):
    exe, digest = binary
    result = gw.start_gateway(toml_path=TOML, binary=exe, expected_sha256=digest, run_dir=tmp_path / "run",
                              port=free_port(), popen=lambda a, **k: FakeProc(dies_with=3), timeout=2,
                              owner=lambda p: None)
    assert result.state == gw.EXITED_EARLY and "code 3" in result.message


def test_a_gateway_that_never_opens_its_port_is_stopped_not_left_running(binary, tmp_path):
    exe, digest = binary
    proc = FakeProc()
    result = gw.start_gateway(toml_path=TOML, binary=exe, expected_sha256=digest, run_dir=tmp_path / "run",
                              port=free_port(), popen=lambda a, **k: proc, timeout=0.6, owner=lambda p: None)
    assert result.state == gw.UNAVAILABLE and proc.killed and "did not open" in result.message


# ------------------------------------------------------------- 5. Windows Application Control

@pytest.mark.parametrize("code", [4551, 1260])
def test_a_windows_block_is_reported_exactly_and_never_retried(binary, tmp_path, code):
    exe, digest = binary
    attempts = []

    def blocked(argv, **kw):
        attempts.append(argv)
        err = OSError(13, "An Application Control policy has blocked this file")
        err.winerror = code
        raise err

    result = gw.start_gateway(toml_path=TOML, binary=exe, expected_sha256=digest, run_dir=tmp_path / "run",
                              port=free_port(), popen=blocked, owner=lambda p: None)
    assert result.state == gw.BLOCKED and len(attempts) == 1
    assert f"Windows error {code}" in result.message and "Application Control" in result.message
    assert "does not work around this" in result.message and "CodeIntegrity" in result.message
    for forbidden in ("Set-MpPreference", "disable", "turn off Smart", "exclusion"):
        assert forbidden.lower() not in result.message.lower().replace("turning protection off", "")


def test_another_start_failure_is_not_mistaken_for_a_block(binary, tmp_path):
    exe, digest = binary

    def broken(argv, **kw):
        raise FileNotFoundError(2, "no such file")

    result = gw.start_gateway(toml_path=TOML, binary=exe, expected_sha256=digest, run_dir=tmp_path / "run",
                              port=free_port(), popen=broken, owner=lambda p: None)
    assert result.state == gw.START_FAILED


# ------------------------------------------------------------- 6. stopping it

def test_stop_ends_only_the_gateway_atlas_recorded_and_only_if_it_is_still_the_verified_binary(binary, tmp_path):
    exe, _ = binary
    run = tmp_path / "run"
    run.mkdir()
    (run / "wokwigw.json").write_text('{"pid": 555, "exe": "x"}', encoding="utf-8")
    killed = []
    ok = gw.stop_gateway(run_dir=run, binary=exe, killer=killed.append, path_of=lambda pid: exe)
    assert ok.state == gw.STOPPED_OK and killed == [555] and not (run / "wokwigw.json").exists()

    (run / "wokwigw.json").write_text('{"pid": 556, "exe": "x"}', encoding="utf-8")
    stale = gw.stop_gateway(run_dir=run, binary=exe, killer=killed.append,
                            path_of=lambda pid: tmp_path / "somebody-elses.exe")
    assert stale.state == gw.NOT_OURS and killed == [555]            # nothing was killed


def test_stop_without_a_record_touches_nothing(tmp_path, binary):
    exe, _ = binary
    killed = []
    result = gw.stop_gateway(run_dir=tmp_path / "empty", binary=exe, killer=killed.append)
    assert result.state == gw.NOT_STARTED_BY_ATLAS and killed == []


# ------------------------------------------------------------- 7. no public gateway, no exposure

def test_nothing_points_at_a_public_gateway_or_tunnel():
    banned = ("ngrok", "trycloudflare", "localtunnel", "wokwi-cli", "gateway.wokwi.com")
    assert not [b for b in banned if b in TOML.read_text(encoding="utf-8")]
    for name in ("wokwi_gateway.py", "run_sim.py"):
        src = (ROOT / "scripts" / name).read_text(encoding="utf-8")
        urls = set(re.findall(r"wss?://[A-Za-z0-9.\-]+(?::\d+)?", src))
        urls.discard("ws://host")                  # the error message's "ws://host:port" format description
        assert urls <= {"ws://localhost:9011"}, f"{name} mentions {urls - {'ws://localhost:9011'}}"


def test_the_helper_only_ever_connects_to_loopback_and_never_binds():
    src = (ROOT / "scripts" / "wokwi_gateway.py").read_text(encoding="utf-8")
    assert gw.HOST == "127.0.0.1" and gw.LOOPBACK_NAMES == {"localhost", "127.0.0.1"}
    assert ".bind(" not in src and ".listen(" not in src and "0.0.0.0" not in src
    connects = re.findall(r"create_connection\(\(([^,)]+)", src)
    assert connects and all(c.strip() == "host" for c in connects)
    # and `host` is only ever the loopback constant
    assert re.findall(r"host: str = (\w+)", src) and set(re.findall(r"host: str = (\w+)", src)) == {"HOST"}


def test_run_sim_keeps_atlas_on_loopback_and_the_helper_is_its_only_gateway_launcher():
    src = (ROOT / "scripts" / "run_sim.py").read_text(encoding="utf-8")
    assert "0.0.0.0" not in src and '"--host"' not in src
    assert '("atlas_service", ["atlas", "--port", "8000", "--tls"])' in src
    assert "wokwi_gateway.start_gateway" in src and "subprocess.Popen([str(gw)" not in src


# ------------------------------------------------------------- 8. run_sim's order

def test_run_sim_says_nothing_was_started_when_a_prerequisite_is_missing(monkeypatch, capsys):
    monkeypatch.setattr(run_sim, "missing_prerequisites", lambda: ["no enrolled policy owner for user-demo-1"])
    monkeypatch.setattr(run_sim, "device_tls_problems", lambda: [])
    monkeypatch.setattr(sys, "argv", ["run_sim.py"])
    started = []
    monkeypatch.setattr(run_sim, "launch", lambda *a, **k: started.append(a))
    monkeypatch.setattr(run_sim.wokwi_gateway, "start_gateway", lambda **k: started.append(k))
    assert run_sim.main() == 2
    out = capsys.readouterr().out
    assert started == []
    assert "Nothing was started" in out and "Failed to connect to the IoT Gateway" in out


def test_run_sim_stops_the_services_and_starts_no_gateway_when_a_service_dies(monkeypatch, capsys, tmp_path):
    monkeypatch.setattr(run_sim, "missing_prerequisites", lambda: [])
    monkeypatch.setattr(run_sim, "device_tls_problems", lambda: [])
    monkeypatch.setattr(sys, "argv", ["run_sim.py"])
    dead = FakeProc(dies_with=1)
    monkeypatch.setattr(run_sim, "launch", lambda *a, **k: [("atlas_service", dead)])
    monkeypatch.setattr(run_sim.wokwi_gateway, "start_gateway",
                        lambda **k: (_ for _ in ()).throw(AssertionError("gateway started after a service died")))
    monkeypatch.setattr(run_sim, "supervise_stop", lambda procs: None)
    assert run_sim.main() == 2
    assert "exited with code 1" in capsys.readouterr().out


def test_ready_is_printed_only_after_the_gateway_is_verified(monkeypatch, capsys):
    order = []
    monkeypatch.setattr(run_sim, "missing_prerequisites", lambda: [])
    monkeypatch.setattr(run_sim, "device_tls_problems", lambda: [])
    monkeypatch.setattr(sys, "argv", ["run_sim.py"])
    monkeypatch.setattr(run_sim, "launch", lambda *a, **k: [("atlas_service", FakeProc())])
    monkeypatch.setattr(run_sim, "wait_for_services", lambda *a, **k: None)
    monkeypatch.setattr(run_sim.wokwi_gateway, "start_gateway",
                        lambda **k: order.append("gateway") or gw.Result(gw.BLOCKED, "BLOCKED BY WINDOWS: x"))
    monkeypatch.setattr(run_sim, "supervise_stop", lambda procs: order.append("stopped"))
    monkeypatch.setattr(run_sim, "supervise", lambda *a, **k: order.append("supervise") or 0)
    assert run_sim.main() == 3                                # a Windows block has its own exit status
    out = capsys.readouterr().out
    assert order == ["gateway", "stopped"] and "READY" not in out


# ------------------------------------------------------------- 9. one canonical procedure

def test_the_runbook_has_one_wokwi_startup_procedure_and_the_firmware_readme_points_at_it():
    runbook = (ROOT / "RUNBOOK.md").read_text(encoding="utf-8")
    assert runbook.count("the one Wokwi startup procedure") == 1
    assert "Failed to connect to the IoT Gateway" in runbook and "wokwi_gateway.py check" in runbook
    assert "BLOCKED_BY_WINDOWS" in runbook and "does not work around it" in runbook
    assert "taskkill /F /IM wokwigw.exe" not in runbook                 # it would kill any wokwigw, not just ours
    firmware = (ROOT / "firmware" / "README.md").read_text(encoding="utf-8")
    assert "RUNBOOK.md` §1" in firmware
    assert not re.search(r"^\s*wokwigw\s*(#.*)?$", firmware, re.M)       # no second, bare 'start wokwigw' recipe
