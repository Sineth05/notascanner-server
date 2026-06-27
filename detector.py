#!/usr/bin/env python3
import os
import sys
import hashlib
import threading
import datetime
import ctypes
import subprocess
import json
from ctypes import wintypes
import tkinter as tk
from tkinter import ttk, messagebox, filedialog

try:
    import psutil
except ImportError:
    print("ERROR: pip install psutil")
    sys.exit(1)

try:
    from PIL import Image, ImageTk, ImageDraw
except ImportError:
    Image = ImageTk = ImageDraw = None

APP_NAME = "NOTA Scanner"
APP_VERSION = "8.0.0"
APP_DIR = os.path.join(os.environ.get('APPDATA', '.'), 'NOTA_Scanner')
os.makedirs(APP_DIR, exist_ok=True)
PROFILE_PIC_PATH = os.path.join(APP_DIR, 'profile_pic.png')
CONFIG_PATH = os.path.join(APP_DIR, 'config.json')
DEFAULT_SERVER_URL = "https://notascanner-pro.vercel.app"

def load_config():
    try:
        if os.path.exists(CONFIG_PATH):
            with open(CONFIG_PATH, 'r') as f:
                return json.load(f)
    except:
        pass
    return {"server_url": DEFAULT_SERVER_URL}

def save_config(cfg):
    try:
        with open(CONFIG_PATH, 'w') as f:
            json.dump(cfg, f, indent=2)
    except:
        pass

def get_hwid():
    try:
        import winreg
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Cryptography")
        guid, _ = winreg.QueryValueEx(key, "MachineGuid")
        winreg.CloseKey(key)
        return guid.strip()
    except:
        try:
            out = subprocess.check_output('wmic csproduct get uuid', shell=True).decode()
            return out.split('\n')[1].strip()
        except:
            import uuid
            return str(uuid.getnode())

def api_request(url, method="GET", data=None, token=None):
    import urllib.request
    try:
        req = urllib.request.Request(url, method=method)
        req.add_header('Content-Type', 'application/json')
        if token:
            req.add_header('Authorization', f'Bearer {token}')
        
        body = None
        if data:
            body = json.dumps(data).encode('utf-8')
            
        with urllib.request.urlopen(req, data=body, timeout=8) as response:
            res_data = response.read().decode('utf-8')
            return json.loads(res_data), response.status
    except urllib.error.HTTPError as e:
        try:
            err_data = e.read().decode('utf-8')
            return json.loads(err_data), e.code
        except:
            return {"error": e.reason}, e.code
    except Exception as e:
        return {"error": str(e)}, 500

EMULATOR_PROCESS_NAMES = [
    "HD-Player.exe", "BlueStacks.exe", "BlueStacksHelper.exe",
    "Ld9BoxHeadless.exe", "LdPlayer.exe", "ld9box.exe",
    "MEmu.exe", "MEmuHeadless.exe", "Nox.exe", "NoxVMHandle.exe",
    "GameLoop.exe", "gameloop.exe", "txgameassistant.exe",
    "MuMuPlayer.exe", "NemuPlayer.exe", "KoPlayer.exe",
]

EMULATOR_FOLDERS = [
    "bluestacks", "ldplayer", "gameloop", "memu", "nox",
    "mumu", "nemu", "koplayer",
]

KNOWN_CHEAT_HASHES = {
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855": "Aimbot Pro",
    "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a": "Wallhack Engine",
}

# Exact cheat tool name keywords — any process/file matching these → Confirmed
CHEAT_NAMES = [
    "internal", "external", "panel", "xiter",
    "aimbot", "wallhack", "triggerbot", "spinbot",
    "bhop", "bunnyhop", "norecoil", "no-recoil",
    "esp32", "cheatengine", "cheat-engine",
    "loaderinject", "injector", "dllinjector",
    "hvh", "legitbot", "ragebot", "backtrack",
    "resolver", "antiaim", "anti-aim",
    "skeet", "neverlose", "onetap", "gamesense",
    "nixware", "aimware", "fatality",
]

SAFE_PROCESSES = {
    "system", "system idle process", "wininit.exe", "winlogon.exe",
    "services.exe", "lsass.exe", "svchost.exe", "smss.exe",
    "csrss.exe", "explorer.exe", "dwm.exe", "ctfmon.exe",
    "conhost.exe", "rundll32.exe", "taskmgr.exe", "cmd.exe",
    "powershell.exe", "notepad.exe", "chrome.exe", "firefox.exe",
    "msedge.exe", "steam.exe", "discord.exe", "spotify.exe",
    "obs64.exe", "vlc.exe", "python.exe", "code.exe",
    "nvcontainer.exe", "nvsphelper64.exe", "amdow.exe",
    "steamwebhelper.exe", "gameoverlayui.exe",
}

SAFE_WINDOW_TITLES = {
    "", "nvidia geforce overlay", "discord overlay",
    "steam overlay", "obs", "streamlabs",
}

SUSPICIOUS_FOLDERS = ["desktop", "downloads", "temp"]


def is_cheat_name(name):
    """Return (True, matched_keyword) if name matches any known cheat tool name."""
    nl = (name or "").lower()
    # Strip extension for cleaner matching
    base = nl.rsplit('.', 1)[0] if '.' in nl else nl
    for kw in CHEAT_NAMES:
        if kw in base or kw in nl:
            return True, kw
    return False, None


def get_emulator_process():
    for proc in psutil.process_iter(['pid', 'name', 'exe']):
        try:
            if proc.info['name'] in EMULATOR_PROCESS_NAMES:
                return proc
        except:
            continue
    return None


# Extended Windows default process/path skips
WINDOWS_DEFAULT_PATHS = [
    "\\windows\\", "\\microsoft\\", "\\windowsapps\\",
    "\\windows defender\\", "\\microsoft.net\\",
    "\\windowspowershell\\", "\\microsoft shared\\",
]

OWN_PROCESS_NAME = os.path.basename(sys.executable).lower()
OWN_SCRIPT_NAME  = os.path.basename(sys.argv[0]).lower() if sys.argv else ""

def is_own_process(name, exe_path=""):
    """True if this process is the scanner itself."""
    nl = (name or "").lower()
    el = (exe_path or "").lower()
    if nl in (OWN_PROCESS_NAME, OWN_SCRIPT_NAME):
        return True
    if OWN_SCRIPT_NAME and OWN_SCRIPT_NAME in el:
        return True
    # Also skip by exe name patterns used when packaged as exe
    if "notascanner" in nl or "notascanner" in el:
        return True
    if "ditector" in nl or "ditector" in el:
        return True
    return False

def is_windows_default_path(fp):
    """True if exe lives in a Windows/Microsoft system folder."""
    f = (fp or "").lower()
    return any(p in f for p in WINDOWS_DEFAULT_PATHS)

def is_safe_process(name):
    n = name.lower() if name else ""
    return n in SAFE_PROCESSES or "netmode" in n


def is_system_process(pid):
    return pid in (0, 4)


def is_in_emulator_folder(fp):
    return any(e in fp.lower() for e in EMULATOR_FOLDERS)


def is_in_program_files(fp):
    f = fp.lower()
    return "\\program files\\" in f or "\\programdata\\" in f


def is_in_system32(fp):
    f = fp.lower()
    return "\\windows\\system32\\" in f or "\\windows\\syswow64\\" in f


def is_suspicious_location(fp):
    return any(s in fp.lower() for s in SUSPICIOUS_FOLDERS)


def get_file_hash(fp):
    try:
        if not os.path.exists(fp) or os.path.getsize(fp) > 50*1024*1024:
            return None
        sha = hashlib.sha256()
        with open(fp, 'rb') as f:
            for chunk in iter(lambda: f.read(8192), b''):
                sha.update(chunk)
        return sha.hexdigest()
    except:
        return None


def is_signed_by_trusted(fp):
    if not fp or not os.path.exists(fp):
        return False
    if is_in_program_files(fp):
        return True
    return False


def kill_process(pid):
    em = get_emulator_process()
    if em and pid == em.pid:
        return False, "Cannot kill emulator"
    try:
        p = psutil.Process(pid)
        n = p.name()
        p.terminate()
        p.wait(timeout=5)
        return True, n
    except:
        try:
            subprocess.run(['taskkill', '/F', '/PID', str(pid)], capture_output=True)
            return True, f"PID:{pid}"
        except:
            return False, ""


def is_safe_window_title(t):
    t = t.lower() if t else ""
    if t in SAFE_WINDOW_TITLES:
        return True
    return any(s in t for s in ["nvidia", "geforce", "discord", "steam", "obs"])


def open_file_location(fp):
    try:
        if os.path.exists(fp):
            subprocess.Popen(['explorer', '/select,', fp])
    except:
        pass


def create_default_profile_pic():
    if Image is None or ImageDraw is None:
        return
    if not os.path.exists(PROFILE_PIC_PATH):
        try:
            img = Image.new('RGB', (80, 80), color='#7c3aed')
            draw = ImageDraw.Draw(img)
            draw.ellipse([10, 10, 70, 70], fill='#a78bfa')
            draw.text((28, 25), "NA", fill='white')
            img.save(PROFILE_PIC_PATH)
        except:
            pass

class DetectionEngine:
    def __init__(self):
        if sys.platform != 'win32':
            raise RuntimeError('NOTA Scanner only supports Windows.')
        self.user32 = ctypes.windll.user32

    def scan(self, mode="deep", stop_flag=None):
        em = get_emulator_process()
        em_pid = em.pid if em else None
        em_name = em.info['name'] if em else "None"
        all_findings = []

        def stopped():
            return stop_flag is not None and stop_flag()

        if em and not stopped():
            all_findings.extend(self._scan_dll_injection(em))
        if not stopped():
            all_findings.extend(self._scan_process_behavior(em_pid, stop_flag))
        if not stopped():
            all_findings.extend(self._scan_overlay_windows())
        if mode in ["medium", "deep"] and not stopped():
            all_findings.extend(self._scan_suspicious_files(stop_flag))
        if mode == "deep" and not stopped():
            all_findings.extend(self._scan_registry())

        confirmed = []
        suspicious = []
        seen = set()

        for f in all_findings:
            key = f"{f.get('name')}_{f.get('type')}_{f.get('risk')}"
            if key in seen:
                continue
            seen.add(key)
            risk = f.get("risk", 0)
            if risk >= 98:
                confirmed.append(f)
            elif risk >= 55:
                suspicious.append(f)

        confirmed.sort(key=lambda x: x["risk"], reverse=True)
        suspicious.sort(key=lambda x: x["risk"], reverse=True)

        return {
            "emulator": em_name,
            "confirmed": confirmed,
            "suspicious": suspicious,
            "confirmed_count": len(confirmed),
            "suspicious_count": len(suspicious),
        }

    def _scan_dll_injection(self, em_proc):
        findings = []
        try:
            dll_list = list(set([dll.path for dll in em_proc.memory_maps() if dll.path.lower().endswith('.dll')]))
            for dll_path in dll_list:
                dll_name = os.path.basename(dll_path)
                if "netmode" in dll_name.lower():
                    continue
                if is_in_system32(dll_path):
                    continue
                if is_in_program_files(dll_path) and is_signed_by_trusted(dll_path):
                    continue
                risk = 0
                reasons = []
                file_hash = get_file_hash(dll_path)
                if file_hash and file_hash in KNOWN_CHEAT_HASHES:
                    risk = 100
                    reasons.append(f"KNOWN CHEAT: {KNOWN_CHEAT_HASHES[file_hash]}")
                if is_in_emulator_folder(dll_path):
                    reasons.append("DLL in emulator folder")
                    risk = max(risk, 90)
                if is_suspicious_location(dll_path):
                    reasons.append("DLL from suspicious location")
                    risk = max(risk, 85)
                if risk >= 55:
                    findings.append({
                        "name": dll_name, "type": "INJECTED DLL",
                        "path": dll_path, "hash": file_hash,
                        "reasons": reasons, "risk": min(risk, 100),
                    })
        except:
            pass
        return findings

    def _scan_process_behavior(self, em_pid, stop_flag=None):
        findings = []
        for proc in psutil.process_iter(['pid', 'name', 'exe']):
            if stop_flag and stop_flag():
                break
            try:
                pname = proc.info['name'] or ""
                pid = proc.info['pid']
                if pid == em_pid or is_system_process(pid) or is_safe_process(pname):
                    continue
                try:
                    exe_path = proc.exe() or ""
                except:
                    exe_path = ""
                # Skip the scanner itself
                if is_own_process(pname, exe_path):
                    continue
                # Skip anything in Windows/Microsoft system folders
                if is_windows_default_path(exe_path):
                    continue
                if is_in_program_files(exe_path):
                    continue
                risk = 0
                reasons = []
                file_hash = get_file_hash(exe_path)
                if file_hash and file_hash in KNOWN_CHEAT_HASHES:
                    risk = 100
                    reasons.append(f"KNOWN CHEAT: {KNOWN_CHEAT_HASHES[file_hash]}")
                # Name-based detection — internal/external/panel/xiter etc.
                matched, kw = is_cheat_name(pname)
                if matched:
                    risk = 100
                    reasons.append(f"Cheat tool name detected: {kw}")
                # Also check exe filename itself
                if exe_path:
                    exe_base = os.path.basename(exe_path)
                    matched2, kw2 = is_cheat_name(exe_base)
                    if matched2 and kw2 != kw:
                        risk = 100
                        reasons.append(f"Cheat filename detected: {kw2}")
                if is_suspicious_location(exe_path):
                    reasons.append("Suspicious location")
                    risk = max(risk, 70)
                wr, w_reasons = self._analyze_process_windows(pid)
                risk = max(risk, wr)
                reasons.extend(w_reasons)
                if risk >= 55:
                    findings.append({
                        "name": pname, "type": "SUSPICIOUS PROCESS",
                        "path": exe_path, "pid": pid, "hash": file_hash,
                        "reasons": reasons, "risk": min(risk, 100),
                    })
            except:
                continue
        return findings

    def _analyze_process_windows(self, pid):
        risk = 0
        reasons = []
        try:
            WNDENUMPROC = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
            found = []
            def cb(hwnd, lp):
                _, wp = ctypes.wintypes.DWORD(), ctypes.wintypes.DWORD()
                self.user32.GetWindowThreadProcessId(hwnd, ctypes.byref(wp))
                if wp.value == pid:
                    length = self.user32.GetWindowTextLengthW(hwnd) + 1
                    buf = ctypes.create_unicode_buffer(length)
                    self.user32.GetWindowTextW(hwnd, buf, length)
                    title = buf.value
                    ex = self.user32.GetWindowLongW(hwnd, -20)
                    vis = self.user32.IsWindowVisible(hwnd)
                    rect = wintypes.RECT()
                    self.user32.GetWindowRect(hwnd, ctypes.byref(rect))
                    found.append({
                        "title": title, "visible": vis,
                        "ex_style": ex, "w": rect.right - rect.left,
                        "h": rect.bottom - rect.top,
                    })
                return True
            self.user32.EnumWindows(WNDENUMPROC(cb), 0)
            for win in found:
                title = win["title"]
                if is_safe_window_title(title) or not title:
                    continue
                layered = bool(win["ex_style"] & 0x80000)
                transparent = bool(win["ex_style"] & 0x20)
                topmost = bool(win["ex_style"] & 0x08)
                if layered and transparent and topmost and not win["visible"]:
                    reasons.append("Hidden overlay")
                    risk = max(risk, 98)
                if win["w"] <= 15 and win["h"] <= 15 and layered:
                    reasons.append("Tiny overlay")
                    risk = max(risk, 95)
        except:
            pass
        return risk, reasons

    def _scan_overlay_windows(self):
        findings = []
        seen = set()
        try:
            WNDENUMPROC = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
            def cb(hwnd, lp):
                length = self.user32.GetWindowTextLengthW(hwnd) + 1
                buf = ctypes.create_unicode_buffer(length)
                self.user32.GetWindowTextW(hwnd, buf, length)
                title = buf.value
                if not title or is_safe_window_title(title) or title in seen:
                    return True
                seen.add(title)
                ex = self.user32.GetWindowLongW(hwnd, -20)
                vis = self.user32.IsWindowVisible(hwnd)
                layered = bool(ex & 0x80000)
                topmost = bool(ex & 0x08)
                if layered and topmost and not vis:
                    findings.append({
                        "name": title, "type": "OVERLAY",
                        "path": f"HWND:{hwnd}", "reasons": ["Hidden overlay"],
                        "risk": 96,
                    })
                return True
            self.user32.EnumWindows(WNDENUMPROC(cb), 0)
        except:
            pass
        return findings

    def _scan_suspicious_files(self, stop_flag=None):
        findings = []
        home = os.path.expanduser("~")
        locations = [
            os.path.join(home, "Desktop"),
            os.path.join(home, "Downloads"),
            os.path.join(home, "Documents"),
            os.path.join(home, "AppData", "Roaming"),
            os.path.join(home, "AppData", "Local", "Temp"),
            os.environ.get("TEMP", "C:\\Windows\\Temp"),
            "C:\\",   # root of C drive (depth-limited below)
        ]
        own_names = {OWN_PROCESS_NAME, OWN_SCRIPT_NAME, "notascanner.exe", "ditector.exe", "ditector.py"}
        keywords = ['hack', 'cheat', 'aim', 'esp', 'wall', 'inject', 'bypass', 'panel']
        for loc in locations:
            if not os.path.exists(loc):
                continue
            try:
                for root, dirs, files in os.walk(loc):
                    depth = root.replace(loc, '').count(os.sep)
                    limit = 1 if loc == "C:\\" else 3
                    if depth > limit:
                        continue
                    for file in files:
                        if stop_flag and stop_flag():
                            break
                        fl = file.lower()
                        # Skip the scanner's own files and netmode files
                        if fl in own_names or "netmode" in fl:
                            continue
                        if os.path.splitext(fl)[1] not in ['.exe', '.dll', '.sys', '.bat', '.vbs', '.ps1', '.py', '.jar']:
                            continue
                        fp = os.path.join(root, file)
                        # Skip Windows/Microsoft system paths
                        if is_windows_default_path(fp):
                            continue
                        try:
                            sz = os.path.getsize(fp)
                            # Skip very large files UNLESS they match a cheat name
                            _, name_kw = is_cheat_name(file)
                            if sz > 10*1024*1024 and not name_kw:
                                continue
                        except:
                            continue
                        risk = 0
                        reasons = []
                        fh = get_file_hash(fp)
                        if fh and fh in KNOWN_CHEAT_HASHES:
                            risk = 100
                            reasons.append("KNOWN CHEAT")
                        # Name-based detection — internal/external/panel/xiter etc.
                        matched, kw = is_cheat_name(file)
                        if matched:
                            risk = 100
                            reasons.append(f"Cheat tool name detected: {kw}")
                        for kw in keywords:
                            if kw in fl:
                                reasons.append(f"Suspicious keyword: {kw}")
                                risk = max(risk, 70)
                                break
                        if risk >= 55:
                            findings.append({
                                "name": file, "type": "CHEAT FILE" if risk == 100 else "SUSPICIOUS FILE",
                                "path": fp, "hash": fh, "reasons": reasons,
                                "risk": min(risk, 100),
                            })
            except:
                continue
        return findings

    def _scan_registry(self):
        findings = []
        keywords = ['cheat', 'hack', 'aim', 'esp', 'inject', 'bypass', 'panel']
        try:
            import win32api, win32con
            paths = [
                (win32con.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
                (win32con.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run"),
            ]
            for hkey_root, subkey in paths:
                try:
                    hk = win32api.RegOpenKeyEx(hkey_root, subkey, 0, win32con.KEY_READ)
                    i = 0
                    while True:
                        try:
                            vn, vd, vt = win32api.RegEnumValue(hk, i)
                            if vd and isinstance(vd, str):
                                for kw in keywords:
                                    if "netmode" in vd.lower():
                                        continue
                                    if kw in vd.lower():
                                        findings.append({
                                            "name": vn or "Default",
                                            "type": "REGISTRY",
                                            "path": f"{subkey}\\{vn}",
                                            "reasons": [f"Suspicious: {kw}"],
                                            "risk": 75,
                                        })
                                        break
                            i += 1
                        except:
                            break
                    win32api.RegCloseKey(hk)
                except:
                    continue
        except:
            pass
        return findings


class LoginApp:
    def __init__(self, root, on_success):
        self.root = root
        self.on_success = on_success
        self.root.title("NOTA Scanner - Security Login")
        self.root.geometry("450x500")
        self.root.configure(bg="#0a0a14")
        self.center_window()
        
        self.c = {
            "bg": "#0a0a14", "card": "#141428", "input": "#1a1a2e",
            "purple": "#7c3aed", "green": "#10b981", "red": "#ef4444",
            "txt": "#e2e8f0", "txt2": "#94a3b8", "txt3": "#64748b"
        }
        
        # Header
        hdr = tk.Frame(self.root, bg=self.c["bg"])
        hdr.pack(pady=30)
        
        tk.Label(hdr, text="🔑 NOTA SECURITY", font=("Segoe UI", 20, "bold"),
                 fg=self.c["purple"], bg=self.c["bg"]).pack()
        tk.Label(hdr, text="Enter credentials to access the scanner", font=("Segoe UI", 10),
                 fg=self.c["txt3"], bg=self.c["bg"]).pack(pady=5)
                 
        # Card container
        card = tk.Frame(self.root, bg=self.c["card"], padx=25, pady=25,
                        highlightbackground="#1e1e3a", highlightthickness=1)
        card.pack(fill=tk.BOTH, expand=True, padx=30, pady=(0, 30))
        
        # Server URL
        tk.Label(card, text="SERVER API URL", font=("Segoe UI", 9, "bold"),
                 fg=self.c["txt2"], bg=self.c["card"]).pack(anchor="w", pady=(0, 5))
        self.cfg = load_config()
        self.server_entry = tk.Entry(card, bg=self.c["input"], fg="white", insertbackground="white",
                                     relief=tk.FLAT, font=("Segoe UI", 10), bd=5)
        self.server_entry.pack(fill=tk.X, pady=(0, 15))
        self.server_entry.insert(0, self.cfg.get("server_url", DEFAULT_SERVER_URL))
        
        # Username
        tk.Label(card, text="USERNAME", font=("Segoe UI", 9, "bold"),
                 fg=self.c["txt2"], bg=self.c["card"]).pack(anchor="w", pady=(0, 5))
        self.user_entry = tk.Entry(card, bg=self.c["input"], fg="white", insertbackground="white",
                                   relief=tk.FLAT, font=("Segoe UI", 10), bd=5)
        self.user_entry.pack(fill=tk.X, pady=(0, 15))
        
        # Password
        tk.Label(card, text="PASSWORD", font=("Segoe UI", 9, "bold"),
                 fg=self.c["txt2"], bg=self.c["card"]).pack(anchor="w", pady=(0, 5))
        self.pass_entry = tk.Entry(card, bg=self.c["input"], fg="white", insertbackground="white",
                                   show="*", relief=tk.FLAT, font=("Segoe UI", 10), bd=5)
        self.pass_entry.pack(fill=tk.X, pady=(0, 15))

        self.hwid_str = get_hwid()
        
        # Login Button
        self.login_btn = tk.Button(card, text="SIGN IN", font=("Segoe UI", 11, "bold"),
                                   bg=self.c["purple"], fg="white", relief=tk.FLAT,
                                   cursor="hand2", pady=8, command=self.attempt_login)
        self.login_btn.pack(fill=tk.X, pady=(10, 10))
        
        # Status Label
        self.status = tk.Label(card, text="", font=("Segoe UI", 9), fg=self.c["red"], bg=self.c["card"], wraplength=300)
        self.status.pack()
        self.card = card
        self.pending_owner_credentials = None
        self.root.after(200, self.focus_window)

    def center_window(self):
        self.root.update_idletasks()
        w, h = 450, 500
        sw, sh = self.root.winfo_screenwidth(), self.root.winfo_screenheight()
        self.root.geometry(f"+{(sw-w)//2}+{(sh-h)//2}")

    def focus_window(self):
        try:
            self.root.deiconify()
            self.root.lift()
            self.root.attributes("-topmost", True)
            self.root.after(500, lambda: self.root.attributes("-topmost", False))
            self.user_entry.focus_set()
        except:
            pass

    def attempt_login(self):
        srv = self.server_entry.get().strip()
        usr = self.user_entry.get().strip()
        pwd = self.pass_entry.get().strip()
        hw = self.hwid_str
        
        if not srv or not usr or not pwd:
            self.status.config(text="All fields are required.", fg=self.c["red"])
            return
            
        self.status.config(text="Connecting...", fg=self.c["purple"])
        self.login_btn.config(state="disabled")
        self.root.update()
        
        self.cfg["server_url"] = srv
        save_config(self.cfg)
        
        def run_auth():
            url = f"{srv.rstrip('/')}/api/auth/login"
            payload = {"username": usr, "password": pwd, "hwid": hw}
            res, code = api_request(url, method="POST", data=payload)
            
            def handle_res():
                self.login_btn.config(state="normal")
                if code == 200 and res.get("requires_master_password"):
                    self.pending_owner_credentials = {"server_url": srv, "username": usr, "password": pwd, "hwid": hw}
                    self.show_master_password_step()
                elif code == 200:
                    self.on_success(res)
                else:
                    err_msg = res.get("error", "Failed to connect to server.")
                    self.status.config(text=f"Error: {err_msg}", fg=self.c["red"])
            self.root.after(0, handle_res)
            
        threading.Thread(target=run_auth, daemon=True).start()

    def show_master_password_step(self):
        for widget in self.card.winfo_children():
            widget.destroy()

        tk.Label(self.card, text="OWNER VERIFICATION", font=("Segoe UI", 13, "bold"),
                 fg=self.c["purple"], bg=self.c["card"]).pack(anchor="w", pady=(0, 8))
        tk.Label(self.card, text=f"Owner account: {self.pending_owner_credentials['username']}", font=("Segoe UI", 9),
                 fg=self.c["txt3"], bg=self.c["card"]).pack(anchor="w", pady=(0, 18))

        tk.Label(self.card, text="MASTER PASSWORD", font=("Segoe UI", 9, "bold"),
                 fg=self.c["txt2"], bg=self.c["card"]).pack(anchor="w", pady=(0, 5))
        self.owner_master_entry = tk.Entry(self.card, bg=self.c["input"], fg="white", insertbackground="white",
                                           show="*", relief=tk.FLAT, font=("Segoe UI", 10), bd=5)
        self.owner_master_entry.pack(fill=tk.X, pady=(0, 15))
        self.owner_master_entry.focus_set()
        self.owner_master_entry.bind("<Return>", lambda e: self.attempt_owner_master_login())

        self.login_btn = tk.Button(self.card, text="ENTER OWNER PANEL", font=("Segoe UI", 11, "bold"),
                                   bg=self.c["purple"], fg="white", relief=tk.FLAT,
                                   cursor="hand2", pady=8, command=self.attempt_owner_master_login)
        self.login_btn.pack(fill=tk.X, pady=(10, 10))

        tk.Button(self.card, text="BACK", font=("Segoe UI", 9, "bold"), bg=self.c["input"], fg=self.c["txt2"],
                  relief=tk.FLAT, cursor="hand2", pady=6, command=self.reset_login_screen).pack(fill=tk.X)

        self.status = tk.Label(self.card, text="", font=("Segoe UI", 9), fg=self.c["red"], bg=self.c["card"], wraplength=300)
        self.status.pack(pady=(10, 0))

    def attempt_owner_master_login(self):
        if not self.pending_owner_credentials:
            self.reset_login_screen()
            return

        master_pwd = self.owner_master_entry.get().strip()
        if not master_pwd:
            self.status.config(text="Master password is required.", fg=self.c["red"])
            return

        self.status.config(text="Verifying owner...", fg=self.c["purple"])
        self.login_btn.config(state="disabled")
        self.root.update()

        creds = self.pending_owner_credentials

        def run_auth():
            url = f"{creds['server_url'].rstrip('/')}/api/auth/login"
            payload = {
                "username": creds["username"],
                "password": creds["password"],
                "hwid": creds["hwid"],
                "master_password": master_pwd
            }
            res, code = api_request(url, method="POST", data=payload)

            def handle_res():
                self.login_btn.config(state="normal")
                if code == 200 and not res.get("requires_master_password"):
                    self.on_success(res)
                else:
                    err_msg = res.get("error", "Failed to verify owner.")
                    self.status.config(text=f"Error: {err_msg}", fg=self.c["red"])
            self.root.after(0, handle_res)

        threading.Thread(target=run_auth, daemon=True).start()

    def reset_login_screen(self):
        for widget in self.root.winfo_children():
            widget.destroy()
        LoginApp(self.root, self.on_success)


class ScannerApp:
    def __init__(self, root, auth_data):
        self.root = root
        self.auth_token = auth_data["token"]
        self.auth_role = auth_data["role"]
        self.auth_username = auth_data["username"]
        self.server_url = load_config().get("server_url", DEFAULT_SERVER_URL).rstrip('/')
        
        self.root.title(f"{APP_NAME} v{APP_VERSION} - Logged in as {self.auth_username} ({self.auth_role.upper()})")
        self.root.geometry("850x700")
        self.root.minsize(750, 600)
        self.root.configure(bg="#0a0a14")
        
        self.engine = DetectionEngine()
        self.last_confirmed = []
        self.last_suspicious = []
        self.active_tab = "confirmed"
        self._stop_scan = False
        self.profile_image = None
        self.center_window()
        self.create_widgets()
        self.load_profile_pic()
        self.refresh_status()

    def center_window(self):
        self.root.update_idletasks()
        w, h = 850, 700
        sw, sh = self.root.winfo_screenwidth(), self.root.winfo_screenheight()
        self.root.geometry(f"+{(sw-w)//2}+{(sh-h)//2}")

    def create_widgets(self):
        c = {
            "bg": "#0a0a14", "card": "#141428", "input": "#1a1a2e",
            "purple": "#7c3aed", "green": "#10b981", "red": "#ef4444",
            "orange": "#f59e0b", "txt": "#e2e8f0", "txt2": "#94a3b8", "txt3": "#64748b"
        }
        self.c = c

        # Top bar
        top = tk.Frame(self.root, bg=c["card"], height=60)
        top.pack(fill=tk.X)
        top.pack_propagate(False)

        self.profile_btn = tk.Label(top, bg=c["purple"], width=6, height=3,
                                     cursor="hand2", text="NA", fg="white",
                                     font=("Segoe UI", 10, "bold"))
        self.profile_btn.pack(side=tk.LEFT, padx=15, pady=8)
        self.profile_btn.bind("<Button-1>", self.change_profile_pic)

        tk.Label(top, text="NOTA Scanner Pro", font=("Segoe UI", 16, "bold"),
                 fg=c["purple"], bg=c["card"]).pack(side=tk.LEFT, padx=5)
        self.emu_label = tk.Label(top, text="No Emulator", font=("Segoe UI", 9),
                                   fg=c["txt2"], bg=c["card"])
        self.emu_label.pack(side=tk.RIGHT, padx=20)

        # Tab Selector Bar (Only for Admin & Owner)
        if self.auth_role in ["admin", "owner"]:
            tabs_bar = tk.Frame(self.root, bg=c["card"], height=40)
            tabs_bar.pack(fill=tk.X, pady=(2, 0))
            tabs_bar.pack_propagate(False)

            self.tab_buttons = {}
            tabs = [("Scanner", self.show_scanner), ("User Manager", self.show_manager), ("Scan Logs", self.show_logs)]
            if self.auth_role == "owner":
                tabs.append(("Owner Settings", self.show_owner_settings))
            for name, cmd in tabs:
                btn = tk.Button(tabs_bar, text=name.upper(), font=("Segoe UI", 9, "bold"),
                                bg=c["card"], fg=c["txt2"], relief=tk.FLAT, padx=15, cursor="hand2",
                                command=cmd)
                btn.pack(side=tk.LEFT, fill=tk.Y)
                self.tab_buttons[name] = btn

        # Main Container
        self.main_container = tk.Frame(self.root, bg=c["bg"])
        self.main_container.pack(fill=tk.BOTH, expand=True, padx=15, pady=10)

        # Default View Load
        self.show_scanner()

    def set_active_tab_btn(self, active_name):
        if self.auth_role not in ["admin", "owner"]:
            return
        for name, btn in self.tab_buttons.items():
            if name == active_name:
                btn.config(bg=self.c["purple"], fg="white")
            else:
                btn.config(bg=self.c["card"], fg=self.c["txt2"])

    def clear_main_container(self):
        for widget in self.main_container.winfo_children():
            widget.destroy()

    # --- TAB 1: SCANNER ---
    def show_scanner(self):
        self.set_active_tab_btn("Scanner")
        self.clear_main_container()
        c = self.c

        # Scan Mode Frame
        sf = tk.Frame(self.main_container, bg=c["card"], padx=15, pady=12)
        sf.pack(fill=tk.X, pady=(0, 10))
        tk.Label(sf, text="SCAN MODE:", font=("Segoe UI", 9, "bold"),
                 fg=c["txt2"], bg=c["card"]).pack(side=tk.LEFT, padx=(0, 10))
        self.mode_var = tk.StringVar(value="deep")
        for txt, mode in [("Basic", "basic"), ("Medium", "medium"), ("Deep", "deep")]:
            btn = tk.Button(sf, text=txt, font=("Segoe UI", 10),
                           bg=c["purple"] if mode == "deep" else c["input"],
                           fg="white" if mode == "deep" else c["txt2"],
                           relief=tk.FLAT, padx=15, pady=6, cursor="hand2",
                           command=lambda m=mode: self.set_mode(m))
            btn.pack(side=tk.LEFT, padx=3)
            
        self.stop_btn = tk.Button(sf, text="STOP", font=("Segoe UI", 11, "bold"),
                                   bg=c["red"], fg="white", relief=tk.FLAT,
                                   padx=15, pady=8, cursor="hand2", command=self.stop_scan,
                                   state=tk.DISABLED)
        self.stop_btn.pack(side=tk.RIGHT, padx=(0, 5))
        self.scan_btn = tk.Button(sf, text="SCAN NOW", font=("Segoe UI", 11, "bold"),
                                   bg=c["purple"], fg="white", relief=tk.FLAT,
                                   padx=20, pady=8, cursor="hand2", command=self.start_scan)
        self.scan_btn.pack(side=tk.RIGHT, padx=5)

        # Status Label
        pf = tk.Frame(self.main_container, bg=c["card"], padx=15, pady=10)
        pf.pack(fill=tk.X, pady=(0, 10))
        self.status_label = tk.Label(pf, text="Ready", font=("Segoe UI", 11, "bold"),
                                      fg=c["txt"], bg=c["card"])
        self.status_label.pack(anchor="w")

        # Results area
        ro = tk.Frame(self.main_container, bg=c["card"])
        ro.pack(fill=tk.BOTH, expand=True)

        tab_bar = tk.Frame(ro, bg=c["card"], padx=10, pady=8)
        tab_bar.pack(fill=tk.X)
        self.result_title = tk.Label(tab_bar, text="", font=("Segoe UI", 13, "bold"), bg=c["card"])
        self.result_title.pack(side=tk.LEFT, padx=(5, 15))
        
        self.tab_confirmed_btn = tk.Button(tab_bar, text="CONFIRMED (0)",
                                           font=("Segoe UI", 10, "bold"),
                                           bg=c["red"], fg="white", relief=tk.FLAT,
                                           padx=12, pady=5, cursor="hand2",
                                           command=lambda: self.switch_tab("confirmed"))
        self.tab_confirmed_btn.pack(side=tk.LEFT, padx=3)
        self.tab_sus_btn = tk.Button(tab_bar, text="SUSPICIOUS (0)",
                                     font=("Segoe UI", 10, "bold"),
                                     bg=c["input"], fg=c["orange"], relief=tk.FLAT,
                                     padx=12, pady=5, cursor="hand2",
                                     command=lambda: self.switch_tab("suspicious"))
        self.tab_sus_btn.pack(side=tk.LEFT, padx=3)

        lf = tk.Frame(ro, bg=c["card"])
        lf.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 10))
        self.result_canvas = tk.Canvas(lf, bg=c["card"], highlightthickness=0)
        scroll = ttk.Scrollbar(lf, orient=tk.VERTICAL)
        self.result_list = tk.Frame(self.result_canvas, bg=c["card"])
        self.result_list.bind("<Configure>", lambda e: self.result_canvas.configure(
            scrollregion=self.result_canvas.bbox("all")))
        self.result_canvas.create_window((0, 0), window=self.result_list, anchor="nw")
        self.result_canvas.configure(yscrollcommand=scroll.set)
        scroll.configure(command=self.result_canvas.yview)
        self.result_canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scroll.pack(side=tk.RIGHT, fill=tk.Y)

        bf = tk.Frame(self.main_container, bg=c["bg"], pady=8)
        bf.pack(fill=tk.X)
        self.kill_btn = tk.Button(bf, text="KILL ALL", font=("Segoe UI", 10, "bold"),
                                   bg=c["red"], fg="white", relief=tk.FLAT,
                                   padx=15, pady=8, cursor="hand2",
                                   command=self.kill_all, state=tk.DISABLED)
        self.kill_btn.pack(side=tk.LEFT, padx=3)
        
        tk.Button(bf, text="EXPORT", font=("Segoe UI", 10), bg=c["input"],
                 fg=c["txt2"], relief=tk.FLAT, padx=15, pady=8, cursor="hand2",
                 command=self.export_report).pack(side=tk.LEFT, padx=3)

        self.switch_tab(self.active_tab)

    def set_mode(self, mode):
        self.mode_var.set(mode)
        sf = self.scan_btn.master
        for widget in sf.winfo_children():
            if isinstance(widget, tk.Button) and widget != self.scan_btn and widget != self.stop_btn:
                m = widget.cget('text').lower()
                active = (m == mode)
                widget.config(
                    bg=self.c['purple'] if active else self.c['input'],
                    fg='white' if active else self.c['txt2']
                )

    def load_profile_pic(self):
        if Image is None or ImageTk is None:
            return
        create_default_profile_pic()
        try:
            img = Image.open(PROFILE_PIC_PATH).resize((45, 45), Image.Resampling.LANCZOS)
            self.profile_image = ImageTk.PhotoImage(img)
            self.profile_btn.configure(image=self.profile_image, text="", width=45, height=45)
        except:
            pass

    def change_profile_pic(self, event=None):
        if Image is None:
            messagebox.showinfo("Unavailable", "Profile pictures are not available in this build.")
            return
        fp = filedialog.askopenfilename(title="Select Picture", filetypes=[("Images", "*.png *.jpg *.jpeg")])
        if fp:
            try:
                Image.open(fp).resize((80, 80), Image.Resampling.LANCZOS).save(PROFILE_PIC_PATH)
                self.load_profile_pic()
            except:
                pass

    def refresh_status(self):
        em = get_emulator_process()
        self.emu_label.config(text=em.info['name'] if em else "No Emulator",
                              fg=self.c["green"] if em else self.c["txt2"])
        self.root.after(5000, self.refresh_status)

    def start_scan(self):
        self._stop_scan = False
        self.scan_btn.config(state=tk.DISABLED, text="Scanning...")
        self.stop_btn.config(state=tk.NORMAL)
        self.kill_btn.config(state=tk.DISABLED)
        self.status_label.config(text=f"Running {self.mode_var.get().title()} Scan...")
        for w in self.result_list.winfo_children():
            w.destroy()
        self.result_title.config(text="")

        def scan_thread():
            result = self.engine.scan(
                mode=self.mode_var.get(),
                stop_flag=lambda: self._stop_scan
            )
            self.root.after(0, self.scan_complete, result)

        threading.Thread(target=scan_thread, daemon=True).start()

    def stop_scan(self):
        self._stop_scan = True
        self.stop_btn.config(state=tk.DISABLED)
        self.scan_btn.config(state=tk.NORMAL, text="SCAN NOW")
        self.status_label.config(text="Scan stopped.", fg=self.c["orange"])

    def scan_complete(self, result):
        if self._stop_scan:
            return
        self.scan_btn.config(state=tk.NORMAL, text="SCAN AGAIN")
        self.stop_btn.config(state=tk.DISABLED)
        confirmed = result.get("confirmed", [])
        suspicious = result.get("suspicious", [])
        self.last_confirmed = confirmed
        self.last_suspicious = suspicious
        cc, sc = len(confirmed), len(suspicious)

        self.tab_confirmed_btn.config(text=f"CONFIRMED ({cc})")
        self.tab_sus_btn.config(
            text=f"SUSPICIOUS ({sc})",
            bg=self.c["orange"] if sc > 0 else self.c["input"],
            fg="white" if sc > 0 else self.c["orange"]
        )

        status_text = "Clean"
        if cc == 0 and sc == 0:
            self.status_label.config(text="System Clean", fg=self.c["green"])
            self.result_title.config(text="", fg=self.c["green"])
            self.kill_btn.config(state=tk.DISABLED)
            cf = tk.Frame(self.result_list, bg=self.c["card"])
            cf.pack(fill=tk.X, pady=30)
            tk.Label(cf, text="OK", font=("Segoe UI", 40), fg=self.c["green"], bg=self.c["card"]).pack()
            tk.Label(cf, text="System is clean!", font=("Segoe UI", 14, "bold"),
                    fg=self.c["green"], bg=self.c["card"]).pack()
        else:
            if cc > 0:
                status_text = "Infected"
                self.status_label.config(text=f"{cc} Cheat(s) Found!", fg=self.c["red"])
                self.kill_btn.config(state=tk.NORMAL)
            else:
                status_text = "Suspicious"
                self.status_label.config(text=f"{sc} Suspicious Item(s)", fg=self.c["orange"])
                self.kill_btn.config(state=tk.DISABLED)
            self.switch_tab("confirmed" if cc > 0 else "suspicious")

        # Report to Backend Server
        def report_scans():
            url = f"{self.server_url}/api/scans/report"
            payload = {
                "findings": {
                    "confirmed_count": cc,
                    "suspicious_count": sc,
                    "confirmed": confirmed,
                    "suspicious": suspicious
                },
                "emulator": result.get("emulator", "None"),
                "status": status_text
            }
            api_request(url, method="POST", data=payload, token=self.auth_token)
        threading.Thread(target=report_scans, daemon=True).start()

    def switch_tab(self, tab):
        self.active_tab = tab
        if not hasattr(self, 'tab_confirmed_btn'):
            return
        self.tab_confirmed_btn.config(
            bg=self.c["red"] if tab == "confirmed" else self.c["input"],
            fg="white" if tab == "confirmed" else self.c["txt3"]
        )
        cc = len(self.last_confirmed)
        sc = len(self.last_suspicious)
        self.tab_sus_btn.config(
            bg=self.c["orange"] if tab == "suspicious" else (self.c["orange"] if sc > 0 else self.c["input"]),
            fg="white" if tab == "suspicious" else ("white" if sc > 0 else self.c["orange"])
        )
        for w in self.result_list.winfo_children():
            w.destroy()
        if tab == "confirmed":
            self.result_title.config(text=f"CONFIRMED: {cc}", fg=self.c["red"] if cc > 0 else self.c["txt2"])
            if self.last_confirmed:
                for item in self.last_confirmed:
                    self._add_row(item, True)
            else:
                tk.Label(self.result_list, text="No confirmed cheats found.",
                         font=("Segoe UI", 11), fg=self.c["txt2"], bg=self.c["card"]).pack(pady=30)
        else:
            self.result_title.config(text=f"SUSPICIOUS: {sc}", fg=self.c["orange"] if sc > 0 else self.c["txt2"])
            if self.last_suspicious:
                for item in self.last_suspicious:
                    self._add_row(item, False)
            else:
                tk.Label(self.result_list, text="Nothing suspicious found.",
                         font=("Segoe UI", 11), fg=self.c["txt2"], bg=self.c["card"]).pack(pady=30)

    def _add_row(self, item, confirmed=True):
        row = tk.Frame(self.result_list, bg=self.c["card"], padx=10, pady=8,
                       highlightbackground="#1e1e3a", highlightthickness=1)
        row.pack(fill=tk.X, pady=3, padx=5)
        risk = item.get("risk", 0)
        color = self.c["red"] if risk >= 98 else self.c["orange"]
        info = tk.Frame(row, bg=self.c["card"])
        info.pack(side=tk.LEFT, fill=tk.X, expand=True)
        tk.Label(info, text=f"{'!' if risk>=98 else '?'} {item['name']}",
                font=("Segoe UI", 10, "bold"), fg=color, bg=self.c["card"]).pack(anchor="w")
        tk.Label(info, text=f"[{item['type']}] Risk: {risk}%",
                font=("Segoe UI", 8), fg=self.c["txt3"], bg=self.c["card"]).pack(anchor="w")
        if item.get("reasons"):
            tk.Label(info, text=" | ".join(item["reasons"][:2]),
                    font=("Segoe UI", 8), fg=self.c["txt2"], bg=self.c["card"],
                    wraplength=450).pack(anchor="w")
        btns = tk.Frame(row, bg=self.c["card"])
        btns.pack(side=tk.RIGHT, padx=(10, 0))
        if item.get("path") and os.path.exists(os.path.dirname(item["path"])):
            tk.Button(btns, text="View Folder", font=("Segoe UI", 8),
                     bg=self.c["input"], fg=self.c["txt"], relief=tk.FLAT,
                     padx=8, pady=4, cursor="hand2",
                     command=lambda p=item["path"]: open_file_location(p)).pack(side=tk.LEFT, padx=2)
        if confirmed and "pid" in item:
            tk.Button(btns, text="Kill", font=("Segoe UI", 8, "bold"),
                     bg=self.c["red"], fg="white", relief=tk.FLAT,
                     padx=8, pady=4, cursor="hand2",
                     command=lambda p=item["pid"]: self.kill_one(p)).pack(side=tk.LEFT, padx=2)

    def kill_one(self, pid):
        em = get_emulator_process()
        if em and pid == em.pid:
            messagebox.showerror("Protected", "Cannot kill emulator.")
            return
        if messagebox.askyesno("Confirm", f"Kill process {pid}?"):
            ok, name = kill_process(pid)
            messagebox.showinfo("Done", f"Killed: {name}" if ok else "Failed")
            if ok:
                self.start_scan()

    def kill_all(self):
        items = [i for i in self.last_confirmed if "pid" in i]
        if not items:
            messagebox.showinfo("Nothing", "No processes to kill.")
            return
        if messagebox.askyesno("Confirm", f"Kill {len(items)} processes?"):
            stopped = sum(1 for i in items if kill_process(i["pid"])[0])
            messagebox.showinfo("Done", f"Killed {stopped}.")
            self.start_scan()

    def export_report(self):
        if not self.last_confirmed and not self.last_suspicious:
            messagebox.showinfo("No Data", "Run a scan first.")
            return
        fp = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text", "*.txt")])
        if not fp:
            return
        try:
            with open(fp, 'w') as f:
                f.write(f"NOTA Scanner v{APP_VERSION} Report\n")
                f.write(f"Date: {datetime.datetime.now()}\n\n")
                f.write(f"CONFIRMED: {len(self.last_confirmed)}\n")
                for i in self.last_confirmed:
                    f.write(f"  [{i['risk']}%] {i['name']} - {i['type']}\n")
                f.write(f"\nSUSPICIOUS: {len(self.last_suspicious)}\n")
                for i in self.last_suspicious:
                    f.write(f"  [{i['risk']}%] {i['name']} - {i['type']}\n")
            messagebox.showinfo("Success", "Report saved!")
        except:
            messagebox.showerror("Error", "Failed.")

    # --- TAB 2: USER MANAGER ---
    def show_manager(self):
        self.set_active_tab_btn("User Manager")
        self.clear_main_container()
        c = self.c

        # Split layout: Left (Add User Form), Right (Accounts List)
        left = tk.Frame(self.main_container, bg=c["card"], padx=20, pady=20,
                        highlightbackground="#1e1e3a", highlightthickness=1)
        left.pack(side=tk.LEFT, fill=tk.BOTH, expand=False, width=300, padx=(0, 10))
        left.pack_propagate(False)

        right = tk.Frame(self.main_container, bg=c["card"], padx=20, pady=20,
                         highlightbackground="#1e1e3a", highlightthickness=1)
        right.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)

        # 1. Left: Add User form
        tk.Label(left, text="CREATE ACCOUNT", font=("Segoe UI", 12, "bold"), fg=c["purple"], bg=c["card"]).pack(anchor="w", pady=(0, 15))
        
        tk.Label(left, text="USERNAME", font=("Segoe UI", 9, "bold"), fg=c["txt2"], bg=c["card"]).pack(anchor="w", pady=(0, 5))
        reg_user = tk.Entry(left, bg=c["input"], fg="white", relief=tk.FLAT, font=("Segoe UI", 10), bd=5)
        reg_user.pack(fill=tk.X, pady=(0, 15))

        tk.Label(left, text="PASSWORD", font=("Segoe UI", 9, "bold"), fg=c["txt2"], bg=c["card"]).pack(anchor="w", pady=(0, 5))
        reg_pass = tk.Entry(left, bg=c["input"], fg="white", relief=tk.FLAT, font=("Segoe UI", 10), bd=5)
        reg_pass.pack(fill=tk.X, pady=(0, 15))

        # Role (Only Owner can select; Admin always creates User accounts)
        reg_role_var = tk.StringVar(value="user")
        if self.auth_role == "owner":
            tk.Label(left, text="ACCOUNT ROLE", font=("Segoe UI", 9, "bold"), fg=c["txt2"], bg=c["card"]).pack(anchor="w", pady=(0, 5))
            role_combo = ttk.Combobox(left, textvariable=reg_role_var, values=["user", "admin"], state="readonly")
            role_combo.pack(fill=tk.X, pady=(0, 15))

        def attempt_create():
            u = reg_user.get().strip()
            p = reg_pass.get().strip()
            r = reg_role_var.get()
            if not u or not p:
                messagebox.showerror("Error", "Please fill in all fields.")
                return
            url = f"{self.server_url}/api/accounts/create"
            res, code = api_request(url, method="POST", data={"username": u, "password": p, "role": r}, token=self.auth_token)
            if code == 200:
                messagebox.showinfo("Success", res.get("message", "Account successfully created."))
                reg_user.delete(0, tk.END)
                reg_pass.delete(0, tk.END)
                load_accounts_list()
            else:
                messagebox.showerror("Error", res.get("error", "Failed to create account."))

        tk.Button(left, text="CREATE ACCOUNT", font=("Segoe UI", 10, "bold"), bg=c["purple"], fg="white",
                  relief=tk.FLAT, cursor="hand2", pady=8, command=attempt_create).pack(fill=tk.X, pady=(10, 0))

        # 2. Right: Accounts list
        tk.Label(right, text="MANAGED ACCOUNTS", font=("Segoe UI", 12, "bold"), fg=c["purple"], bg=c["card"]).pack(anchor="w", pady=(0, 10))

        canvas = tk.Canvas(right, bg=c["card"], highlightthickness=0)
        scroll = ttk.Scrollbar(right, orient=tk.VERTICAL, command=canvas.yview)
        list_frame = tk.Frame(canvas, bg=c["card"])
        list_frame.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.create_window((0, 0), window=list_frame, anchor="nw")
        canvas.configure(yscrollcommand=scroll.set)
        canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scroll.pack(side=tk.RIGHT, fill=tk.Y)

        def load_accounts_list():
            for w in list_frame.winfo_children():
                w.destroy()
            url = f"{self.server_url}/api/accounts"
            res, code = api_request(url, token=self.auth_token)
            if code == 200:
                if not res:
                    tk.Label(list_frame, text="No accounts found.", font=("Segoe UI", 10), fg=c["txt3"], bg=c["card"]).pack(pady=20)
                    return
                for acc in res:
                    row = tk.Frame(list_frame, bg=c["card"], pady=8, highlightbackground="#1e1e3a", highlightthickness=1)
                    row.pack(fill=tk.X, pady=3, ipady=3)
                    
                    info = tk.Frame(row, bg=c["card"])
                    info.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=10)
                    
                    tk.Label(info, text=f"{acc['username']} ({acc['role'].upper()})", font=("Segoe UI", 10, "bold"), fg=c["txt"], bg=c["card"]).pack(anchor="w")
                    if acc["role"] != "owner":
                        hwid_lbl = acc['hwid'] if acc['hwid'] else "Not bound"
                        tk.Label(info, text=f"HWID: {hwid_lbl[:24] + '...' if len(hwid_lbl) > 24 else hwid_lbl}", font=("Segoe UI", 8), fg=c["txt3"], bg=c["card"]).pack(anchor="w")
                    if self.auth_role == "owner":
                        tk.Label(info, text=f"Created By: {acc.get('created_by', 'system')}", font=("Segoe UI", 7), fg=c["txt3"], bg=c["card"]).pack(anchor="w")
                        tk.Label(info, text=f"Limit: {acc.get('max_creations', 10)} | Expiry: {acc.get('expiry_date') or 'Never'}", font=("Segoe UI", 7), fg=c["txt3"], bg=c["card"]).pack(anchor="w")

                        controls = tk.Frame(info, bg=c["card"])
                        controls.pack(fill=tk.X, pady=(6, 0))

                        tk.Label(controls, text="Max", font=("Segoe UI", 7, "bold"), fg=c["txt3"], bg=c["card"]).pack(side=tk.LEFT)
                        max_entry = tk.Entry(controls, bg=c["input"], fg="white", relief=tk.FLAT, width=5, font=("Segoe UI", 8))
                        max_entry.insert(0, str(acc.get("max_creations", 10)))
                        max_entry.pack(side=tk.LEFT, padx=(4, 8))

                        tk.Label(controls, text="Expiry", font=("Segoe UI", 7, "bold"), fg=c["txt3"], bg=c["card"]).pack(side=tk.LEFT)
                        expiry_entry = tk.Entry(controls, bg=c["input"], fg="white", relief=tk.FLAT, width=12, font=("Segoe UI", 8))
                        expiry_entry.insert(0, acc.get("expiry_date") or "")
                        expiry_entry.pack(side=tk.LEFT, padx=(4, 8))

                        def save_limits_fn(username_to_update=acc['username'], max_widget=max_entry, expiry_widget=expiry_entry):
                            payload = {
                                "username": username_to_update,
                                "max_creations": max_widget.get().strip(),
                                "expiry_date": expiry_widget.get().strip()
                            }
                            u_url = f"{self.server_url}/api/accounts/update-limits"
                            u_res, u_code = api_request(u_url, method="POST", data=payload, token=self.auth_token)
                            if u_code == 200:
                                messagebox.showinfo("Success", u_res.get("message", "Account settings updated."))
                                load_accounts_list()
                            else:
                                messagebox.showerror("Error", u_res.get("error", "Failed to update account settings."))

                        tk.Button(controls, text="SAVE", font=("Segoe UI", 7, "bold"), bg=c["purple"], fg="white",
                                  relief=tk.FLAT, cursor="hand2", padx=8, command=save_limits_fn).pack(side=tk.LEFT)
                        
                    def reset_hwid_fn(username_to_reset=acc['username']):
                        if messagebox.askyesno("Confirm", f"Reset HWID lock for {username_to_reset}?"):
                            r_url = f"{self.server_url}/api/accounts/reset-hwid"
                            r_res, r_code = api_request(r_url, method="POST", data={"username": username_to_reset}, token=self.auth_token)
                            if r_code == 200:
                                messagebox.showinfo("Success", "HWID reset successfully.")
                                load_accounts_list()
                            else:
                                messagebox.showerror("Error", r_res.get("error", "Failed to reset HWID."))

                    if acc["role"] != "owner":
                        tk.Button(row, text="RESET HWID", font=("Segoe UI", 8, "bold"), bg=c["input"], fg=c["orange"],
                                  relief=tk.FLAT, cursor="hand2", padx=10, command=reset_hwid_fn).pack(side=tk.RIGHT, padx=10)
            else:
                tk.Label(list_frame, text="Failed to fetch accounts list.", font=("Segoe UI", 10), fg=c["red"], bg=c["card"]).pack(pady=20)

        load_accounts_list()

    # --- TAB 3: OWNER SETTINGS ---
    def show_owner_settings(self):
        if self.auth_role != "owner":
            messagebox.showerror("Access Denied", "Only the Owner can open settings.")
            return

        self.set_active_tab_btn("Owner Settings")
        self.clear_main_container()
        c = self.c

        panel = tk.Frame(self.main_container, bg=c["card"], padx=25, pady=25,
                         highlightbackground="#1e1e3a", highlightthickness=1)
        panel.pack(fill=tk.X, padx=80, pady=40)

        tk.Label(panel, text="OWNER SETTINGS", font=("Segoe UI", 13, "bold"), fg=c["purple"], bg=c["card"]).pack(anchor="w", pady=(0, 18))
        tk.Label(panel, text="MASTER PASSWORD", font=("Segoe UI", 9, "bold"), fg=c["txt2"], bg=c["card"]).pack(anchor="w", pady=(0, 5))

        master_var = tk.StringVar()
        master_entry = tk.Entry(panel, textvariable=master_var, bg=c["input"], fg="white", insertbackground="white",
                                show="*", relief=tk.FLAT, font=("Segoe UI", 10), bd=5)
        master_entry.pack(fill=tk.X, pady=(0, 12))

        status = tk.Label(panel, text="", font=("Segoe UI", 9), fg=c["txt3"], bg=c["card"])
        status.pack(anchor="w", pady=(0, 12))

        def load_master_password():
            url = f"{self.server_url}/api/settings/master-password"
            res, code = api_request(url, token=self.auth_token)
            if code == 200:
                master_var.set(res.get("master_password", ""))
                status.config(text="Current master password loaded.", fg=c["green"])
            else:
                status.config(text=res.get("error", "Failed to load master password."), fg=c["red"])

        def save_master_password():
            value = master_var.get().strip()
            if not value:
                messagebox.showerror("Error", "Master password is required.")
                return
            url = f"{self.server_url}/api/settings/master-password"
            res, code = api_request(url, method="POST", data={"master_password": value}, token=self.auth_token)
            if code == 200:
                status.config(text=res.get("message", "Master password updated."), fg=c["green"])
                messagebox.showinfo("Success", "Master password updated successfully.")
            else:
                status.config(text=res.get("error", "Failed to update master password."), fg=c["red"])

        btns = tk.Frame(panel, bg=c["card"])
        btns.pack(fill=tk.X)
        tk.Button(btns, text="SAVE MASTER PASSWORD", font=("Segoe UI", 10, "bold"), bg=c["purple"], fg="white",
                  relief=tk.FLAT, cursor="hand2", padx=12, pady=8, command=save_master_password).pack(side=tk.LEFT)
        tk.Button(btns, text="RELOAD", font=("Segoe UI", 10, "bold"), bg=c["input"], fg=c["txt2"],
                  relief=tk.FLAT, cursor="hand2", padx=12, pady=8, command=load_master_password).pack(side=tk.LEFT, padx=10)

        load_master_password()

    # --- TAB 4: SCAN LOGS ---
    def show_logs(self):
        self.set_active_tab_btn("Scan Logs")
        self.clear_main_container()
        c = self.c

        hdr = tk.Frame(self.main_container, bg=c["card"], padx=15, pady=10)
        hdr.pack(fill=tk.X, pady=(0, 10))
        tk.Label(hdr, text="CENTRAL MONITORING LOGS", font=("Segoe UI", 12, "bold"), fg=c["purple"], bg=c["card"]).pack(side=tk.LEFT)
        
        canvas = tk.Canvas(self.main_container, bg=c["card"], highlightthickness=0)
        scroll = ttk.Scrollbar(self.main_container, orient=tk.VERTICAL, command=canvas.yview)
        list_frame = tk.Frame(canvas, bg=c["card"])
        list_frame.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.create_window((0, 0), window=list_frame, anchor="nw")
        canvas.configure(yscrollcommand=scroll.set)
        canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scroll.pack(side=tk.RIGHT, fill=tk.Y)

        def refresh_logs():
            for w in list_frame.winfo_children():
                w.destroy()
            url = f"{self.server_url}/api/scans"
            res, code = api_request(url, token=self.auth_token)
            if code == 200:
                if not res:
                    tk.Label(list_frame, text="No scan history found.", font=("Segoe UI", 10), fg=c["txt3"], bg=c["card"]).pack(pady=30)
                    return
                for scan in res:
                    row = tk.Frame(list_frame, bg=c["card"], pady=8, highlightbackground="#1e1e3a", highlightthickness=1)
                    row.pack(fill=tk.X, pady=3, ipady=3)
                    
                    info = tk.Frame(row, bg=c["card"])
                    info.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=10)
                    
                    status_col = c["green"] if scan["status"] == "Clean" else (c["orange"] if scan["status"] == "Suspicious" else c["red"])
                    tk.Label(info, text=f"👤 {scan['username']} - STATUS: {scan['status'].upper()}", font=("Segoe UI", 10, "bold"), fg=status_col, bg=c["card"]).pack(anchor="w")
                    if self.auth_role == "owner":
                        tk.Label(info, text=f"Admin: {scan.get('created_by') or 'system'}", font=("Segoe UI", 8), fg=c["txt2"], bg=c["card"]).pack(anchor="w")
                    tk.Label(info, text=f"Emulator: {scan['emulator']} | Time: {scan['timestamp']}", font=("Segoe UI", 8), fg=c["txt3"], bg=c["card"]).pack(anchor="w")
                    
                    try:
                        f_data = json.loads(scan["findings"])
                        conf_c = len(f_data.get("confirmed", []))
                        sus_c = len(f_data.get("suspicious", []))
                        tk.Label(info, text=f"Flags: {conf_c} Confirmed, {sus_c} Suspicious", font=("Segoe UI", 8), fg=c["txt2"], bg=c["card"]).pack(anchor="w")
                    except:
                        pass
            else:
                tk.Label(list_frame, text="Error loading scan logs.", font=("Segoe UI", 10), fg=c["red"], bg=c["card"]).pack(pady=30)

        tk.Button(hdr, text="REFRESH LOGS", font=("Segoe UI", 9, "bold"), bg=c["purple"], fg="white",
                  relief=tk.FLAT, cursor="hand2", padx=10, command=refresh_logs).pack(side=tk.RIGHT)
        refresh_logs()


def main():
    os.makedirs(APP_DIR, exist_ok=True)
    create_default_profile_pic()
    root = tk.Tk()
    
    def on_login_success(auth_data):
        for w in root.winfo_children():
            w.destroy()
        ScannerApp(root, auth_data)
        
    LoginApp(root, on_login_success)
    root.protocol("WM_DELETE_WINDOW", root.destroy)
    root.mainloop()


if __name__ == "__main__":
    main()
