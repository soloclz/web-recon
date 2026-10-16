"""Verify real Kali dig and Gobuster parsing against a local DNS stub."""

from pathlib import Path
from tempfile import mkdtemp
from threading import Thread
from unittest.mock import patch
import json
import socket
import socketserver
import struct
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from webrecon.dns import run_dns


TARGET = "lab.webrecon.test"
ANSWERS = {TARGET: "10.9.8.1", f"admin.{TARGET}": "10.9.8.7"}


class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        request, udp = self.request
        if len(request) < 17:
            return
        offset = 12
        labels = []
        while offset < len(request):
            length = request[offset]
            offset += 1
            if length == 0:
                break
            labels.append(request[offset: offset + length].decode("ascii").lower())
            offset += length
        if offset + 4 > len(request):
            return
        name = ".".join(labels)
        qtype, qclass = struct.unpack("!HH", request[offset:offset + 4])
        question = request[12:offset + 4]
        address = ANSWERS.get(name) if qtype == 1 and qclass == 1 else None
        rcode = 0 if name in ANSWERS else 3
        header = request[:2] + struct.pack("!HHHHH", 0x8180 | rcode, 1,
                                             1 if address else 0, 0, 0)
        response = header + question
        if address:
            response += (b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4)
                         + socket.inet_aton(address))
        udp.sendto(response, self.client_address)


root = Path(mkdtemp(prefix="web-recon-dns-"))
wordlist = root / "prefixes.txt"
wordlist.write_text("admin\nabsent\n")
server = socketserver.ThreadingUDPServer(("127.0.0.1", 0), Handler)
Thread(target=server.serve_forever, daemon=True).start()
original_run = subprocess.run


def local_resolver(argv, **kwargs):
    if argv[0] == "dig":
        argv = [*argv, "@127.0.0.1", "-p", str(server.server_address[1])]
    elif argv[0] == "gobuster":
        argv = [*argv, "--resolver", f"127.0.0.1:{server.server_address[1]}",
                "--no-progress", "--threads", "1"]
    return original_run(argv, **kwargs)


try:
    with patch("webrecon.dns.subprocess.run", side_effect=local_resolver):
        report = run_dns(TARGET, ["10.9.8.1"], wordlist, root / "output")
    evidence = {
        "fixture_resolver": f"127.0.0.1:{server.server_address[1]}",
        "status": report["status"],
        "A": report["records"]["A"],
        "wildcard": report["wildcard"],
        "scanner": report["scanner"],
        "candidates": report["candidates"],
        "diagnostics": report["diagnostics"],
    }
    (root / "verification.json").write_text(json.dumps(evidence, indent=2) + "\n")
    print(root)
    print(json.dumps(evidence, indent=2))
    assert report["status"] == "completed", report["diagnostics"]
    assert report["records"]["A"] == ["10.9.8.1"]
    assert not report["wildcard"]["detected"]
    assert report["scanner"]["status"] == "completed"
    assert any(item["name"] == f"admin.{TARGET}" for item in report["candidates"])
finally:
    server.shutdown()
