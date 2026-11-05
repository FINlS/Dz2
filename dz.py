import random
import select
import socket
import struct
import sys

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 53
ROOTS = [
    "198.41.0.4",
    "170.247.170.2",
    "192.33.4.12",
    "199.7.91.13",
    "192.203.230.10",
    "192.5.5.241",
    "192.112.36.4",
    "198.97.190.53",
    "192.36.148.17",
    "192.58.128.30",
    "193.0.14.129",
    "199.7.83.42",
    "202.12.27.33",
]


def encode_name(name):
    result = b""
    for label in name.split("."):
        if label:
            result += bytes([len(label)]) + label.encode("latin-1")
    return result + b"\x00"


def parse_name(data, offset):
    labels = []
    end = 0
    jumped = False
    jumps = 0
    while True:
        length = data[offset]
        if length & 0xC0 == 0xC0:
            jumps += 1
            if jumps > 20:
                raise ValueError("loop")
            if not jumped:
                end = offset + 2
            jumped = True
            offset = ((length & 0x3F) << 8) | data[offset + 1]
        elif length == 0:
            if not jumped:
                end = offset + 1
            break
        else:
            labels.append(data[offset + 1:offset + 1 + length].decode("latin-1"))
            offset += 1 + length
    return ".".join(labels), end


def read_record(data, offset):
    name, offset = parse_name(data, offset)
    rtype, rclass, ttl, length = struct.unpack("!HHIH", data[offset:offset + 10])
    offset += 10
    value = None
    if rtype == 1:
        value = socket.inet_ntoa(data[offset:offset + 4])
    elif rtype in (2, 5):
        value, _ = parse_name(data, offset)
    return (name, rtype, ttl, value), offset + length


def parse_response(data):
    qid, flags, qd, an, ns, ar = struct.unpack("!HHHHHH", data[:12])
    offset = 12
    for _ in range(qd):
        _, offset = parse_name(data, offset)
        offset += 4
    sections = []
    for count in (an, ns, ar):
        records = []
        for _ in range(count):
            record, offset = read_record(data, offset)
            records.append(record)
        sections.append(records)
    return flags & 15, sections[0], sections[1], sections[2]


def recv_exact(sock, count):
    data = b""
    while len(data) < count:
        part = sock.recv(count - len(data))
        if not part:
            raise ConnectionError
        data += part
    return data


def ask(ip, name):
    packet = struct.pack("!HHHHHH", random.randint(0, 65535), 0, 1, 0, 0, 0)
    packet += encode_name(name) + struct.pack("!HH", 1, 1)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(3)
        s.sendto(packet, (ip, 53))
        data, _ = s.recvfrom(4096)
    if data[:2] != packet[:2]:
        raise ValueError("wrong id")
    flags = struct.unpack("!H", data[2:4])[0]
    if flags & 0x0200:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(3)
            s.connect((ip, 53))
            s.sendall(struct.pack("!H", len(packet)) + packet)
            length = struct.unpack("!H", recv_exact(s, 2))[0]
            data = recv_exact(s, length)
    return data


def resolve(name, depth=0):
    if depth > 8:
        return 2, []
    servers = list(ROOTS)
    for _ in range(15):
        response = None
        for ip in servers:
            try:
                response = parse_response(ask(ip, name))
                break
            except Exception:
                continue
        if response is None:
            return 2, []
        rcode, answers, authority, additional = response
        if rcode != 0:
            return rcode, []
        if answers:
            last = answers[-1]
            if last[1] == 5 and not any(r[1] == 1 for r in answers):
                rcode, more = resolve(last[3], depth + 1)
                return rcode, answers + more
            return 0, answers
        ns_names = [r[3].lower() for r in authority if r[1] == 2]
        if not ns_names:
            return 0, []
        ips = [r[3] for r in additional if r[1] == 1 and r[0].lower() in ns_names]
        if not ips:
            for ns_name in ns_names:
                rcode, found = resolve(ns_name, depth + 1)
                ips = [r[3] for r in found if r[1] == 1]
                if ips:
                    break
        if not ips:
            return 2, []
        servers = ips
    return 2, []


def get_answers(name):
    lower = name.lower()
    if ".multiply." in lower:
        try:
            product = 1
            for number in lower.split(".multiply.")[0].split("."):
                product *= int(number)
            return 0, [(name, 1, 60, "127.0.0.%d" % (product % 256))]
        except ValueError:
            pass
    return resolve(name)


def handle(data, udp):
    qid, flags = struct.unpack("!HH", data[:4])
    name, offset = parse_name(data, 12)
    qtype, qclass = struct.unpack("!HH", data[offset:offset + 4])
    question = data[12:offset + 4]
    if qtype == 1:
        rcode, answers = get_answers(name)
    else:
        rcode, answers = 0, []
    body = b""
    count = 0
    for rname, rtype, ttl, value in answers:
        if rtype == 1:
            rdata = socket.inet_aton(value)
        elif rtype == 5:
            rdata = encode_name(value)
        else:
            continue
        body += encode_name(rname) + struct.pack("!HHIH", rtype, 1, ttl, len(rdata)) + rdata
        count += 1
    head_flags = 0x8000 | (flags & 0x0100) | 0x0080 | rcode
    response = struct.pack("!HHHHHH", qid, head_flags, 1, count, 0, 0) + question + body
    if udp and len(response) > 512:
        response = struct.pack("!HHHHHH", qid, head_flags | 0x0200, 1, 0, 0, 0) + question
    return response


def answer_tcp(conn):
    conn.settimeout(5)
    try:
        length = struct.unpack("!H", recv_exact(conn, 2))[0]
        data = recv_exact(conn, length)
        response = handle(data, False)
        conn.sendall(struct.pack("!H", len(response)) + response)
    except Exception:
        pass
    conn.close()


udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
udp_sock.bind(("0.0.0.0", PORT))
tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
tcp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
tcp_sock.bind(("0.0.0.0", PORT))
tcp_sock.listen()

while True:
    ready, _, _ = select.select([udp_sock, tcp_sock], [], [])
    for sock in ready:
        if sock is udp_sock:
            data, addr = udp_sock.recvfrom(4096)
            try:
                udp_sock.sendto(handle(data, True), addr)
            except Exception:
                pass
        else:
            conn, _ = tcp_sock.accept()
            answer_tcp(conn)
