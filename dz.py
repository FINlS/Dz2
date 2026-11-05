import math
import random
import socket
import struct
import threading


def pack_name(name):
    return b"".join(bytes([len(p)]) + p.encode() for p in name.split(".") if p) + b"\0"


def read_name(m, o):
    parts, end = [], None
    while m[o]:
        if m[o] & 0xC0 == 0xC0:
            end = end or o + 2
            o = struct.unpack("!H", m[o:o + 2])[0] & 0x3FFF
        else:
            parts.append(m[o + 1:o + 1 + m[o]].decode())
            o += m[o] + 1
    return ".".join(parts), end or o + 1


def read_records(m, o, n):
    out = []
    for _ in range(n):
        name, o = read_name(m, o)
        t, _, ttl, ln = struct.unpack("!HHIH", m[o:o + 10])
        o += 10
        rd = m[o:o + ln]
        if t in (2, 5):
            rd = pack_name(read_name(m, o)[0])
        out.append((name, t, ttl, rd))
        o += ln
    return out, o


def multiply(name):
    parts = name.split(".")
    if "multiply" in parts:
        nums = parts[:parts.index("multiply")]
        if nums and all(n.isdigit() for n in nums):
            return "127.0.0.%d" % (math.prod(map(int, nums)) % 256)


def resolve(name):
    ip = multiply(name)
    if ip:
        return [(name, 1, 60, socket.inet_aton(ip))]

    server = "198.41.0.4"
    for _ in range(15):
        query = (struct.pack("!HHHHHH", random.randrange(65536), 0, 1, 0, 0, 0)
                 + pack_name(name) + struct.pack("!HH", 1, 1))
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(2)
            try:
                s.sendto(query, (server, 53))
                data, _ = s.recvfrom(4096)
            except OSError:
                return []

        an, ns, ar = struct.unpack("!HHH", data[6:12])
        o = read_name(data, 12)[1] + 4
        answers, o = read_records(data, o, an)
        auth, o = read_records(data, o, ns)
        extra, _ = read_records(data, o, ar)

        if answers:
            if answers[-1][1] == 5:
                return answers + resolve(read_name(answers[-1][3], 0)[0])
            return answers

        ns_names = [read_name(r[3], 0)[0].lower() for r in auth if r[1] == 2]
        if not ns_names:
            return []
        glue = [socket.inet_ntoa(r[3]) for r in extra if r[1] == 1 and r[0].lower() in ns_names]
        glue = glue or [socket.inet_ntoa(r[3]) for r in resolve(ns_names[0]) if r[1] == 1]
        if not glue:
            return []
        server = glue[0]
    return []


sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(("127.0.0.1", 5354))


def handle(data, addr):
    try:
        name, o = read_name(data, 12)
        qtype = struct.unpack("!H", data[o:o + 2])[0]
        answers = resolve(name.lower()) if qtype == 1 else []
        resp = data[:2] + struct.pack("!HHHHH", 0x8180, 1, len(answers), 0, 0) + data[12:o + 4]
        for n, t, ttl, rd in answers:
            resp += pack_name(n) + struct.pack("!HHIH", t, 1, ttl, len(rd)) + rd
        sock.sendto(resp, addr)
    except Exception:
        pass


while True:
    data, addr = sock.recvfrom(512)
    threading.Thread(target=handle, args=(data, addr), daemon=True).start()
