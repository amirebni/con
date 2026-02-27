import requests
import base64
import json
import urllib.parse
import os

RAW_URL = os.environ.get("https://raw.githubusercontent.com/punez/Repo-5/refs/heads/main/alive.txt")
OUTPUT = "config.yaml"

def fetch(url):
    r = requests.get(url, timeout=20)
    r.raise_for_status()
    text = r.text.strip()

    # try base64
    try:
        padded = text + "=" * (-len(text) % 4)
        decoded = base64.b64decode(padded).decode("utf-8", errors="ignore")
        if "://" in decoded:
            return decoded
    except:
        pass

    return text

def parse_vmess(link):
    raw = link.replace("vmess://", "")
    raw += "=" * (-len(raw) % 4)
    d = json.loads(base64.b64decode(raw).decode("utf-8", errors="ignore"))
    return {
        "name": d.get("ps", "vmess"),
        "type": "vmess",
        "server": d.get("add"),
        "port": int(d.get("port")),
        "uuid": d.get("id"),
        "alterId": int(d.get("aid", 0)),
        "cipher": "auto",
        "tls": d.get("tls") == "tls",
        "network": d.get("net", "tcp"),
        "ws-opts": {
            "path": d.get("path", "/"),
            "headers": {"Host": d.get("host", "")}
        } if d.get("net") == "ws" else None
    }

def parse_vless_trojan(link, proto):
    u = urllib.parse.urlparse(link)
    q = urllib.parse.parse_qs(u.query)
    return {
        "name": u.fragment or proto,
        "type": proto,
        "server": u.hostname,
        "port": u.port or 443,
        "uuid": u.username,
        "tls": True,
        "network": q.get("type", ["tcp"])[0]
    }

def convert(text):
    proxies = []
    for l in text.splitlines():
        l = l.strip()
        try:
            if l.startswith("vmess://"):
                proxies.append(parse_vmess(l))
            elif l.startswith("vless://"):
                proxies.append(parse_vless_trojan(l, "vless"))
            elif l.startswith("trojan://"):
                proxies.append(parse_vless_trojan(l, "trojan"))
        except:
            continue
    return proxies

def build_yaml(proxies):
    y = """port: 7890
socks-port: 7891
allow-lan: false
mode: rule
log-level: silent

proxies:
"""
    for p in proxies:
        y += f"""  - name: "{p['name']}"
    type: {p['type']}
    server: {p['server']}
    port: {p['port']}
"""
        if p["type"] in ["vmess", "vless"]:
            y += f"    uuid: {p['uuid']}\n"
        else:
            y += f"    password: {p['uuid']}\n"

        if p.get("tls"):
            y += "    tls: true\n"
        y += "\n"

    y += "proxy-groups:\n  - name: AUTO\n    type: select\n    proxies:\n"
    for p in proxies:
        y += f"      - \"{p['name']}\"\n"

    y += "\nrules:\n  - MATCH,AUTO\n"
    return y

print("Fetching raw...")
content = fetch(RAW_URL)

print("Converting...")
proxies = convert(content)

print(f"Nodes: {len(proxies)}")

with open(OUTPUT, "w", encoding="utf-8") as f:
    f.write(build_yaml(proxies))

print("Done ✔ config.yaml created")
