"""
NovaVault Bank - Bank Account Management System (plain Python, desktop window)

"""
import csv
import hashlib
import hmac
import json
import math
import os
import random
import re
import shutil
import time
import tkinter as tk
from datetime import date, datetime
from tkinter import filedialog, messagebox, simpledialog, ttk
from tkinter import font as tkfont

try:
    from PIL import Image, ImageDraw, ImageOps, ImageTk
    HAVE_PIL = True
except Exception:
    HAVE_PIL = False

# ---------------- Settings ----------------
DATA_FILE = "accounts.json"
AVATAR_DIR = "avatars"          # profile photos are saved here as <account number>.png
MAX_AVATAR_BYTES = 2_000_000    # 2 MB photo limit
MIN_BALANCE = {"Savings": 500.0, "Current": 0.0}  # also the minimum opening deposit
DAILY_LIMIT = 50000.0           # max money going out per day (withdraw + transfer)
MAX_DEPOSIT = 1000000.0         # max single deposit
MAX_ATTEMPTS = 3                # wrong PINs before lock
LOCK_SECONDS = 300              # lock time (5 minutes)
INTEREST_RATE = 4.0             # yearly % for Savings accounts
SESSION_TIMEOUT = 600           # auto logout after 10 minutes without activity
SECURITY_QUESTIONS = [
    "What is your pet's name?",
    "What is your mother's maiden name?",
    "What was your first school?",
    "What is your favourite teacher's name?",
    "In which city were you born?",
]
MONEY_IN = ("Opening Deposit", "Deposit", "Transfer In", "Interest")
MONEY_OUT = ("Withdraw", "Transfer Out")


def money(value):
    return f"\u20b9 {value:,.2f}"


def valid_pin(pin):
    return pin.isdigit() and 4 <= len(pin) <= 8


def new_ref():
    """Short unique reference number for every transaction."""
    return "TXN" + os.urandom(4).hex().upper()


def to_float(text):
    """Turn typed text into a number. Returns None for anything that is not a normal number
    (so 'nan' and 'inf' can never reach a balance)."""
    try:
        value = float(str(text).replace(",", "").strip())
    except ValueError:
        return None
    return value if math.isfinite(value) else None


def get_admin_password():
    """Admin password: ADMIN_PASSWORD environment variable, or admin_password.txt."""
    if os.environ.get("ADMIN_PASSWORD"):
        return os.environ["ADMIN_PASSWORD"]
    try:
        with open("admin_password.txt", encoding="utf-8") as f:
            return f.readline().strip() or None
    except OSError:
        return None


# ---------------- profile photos ----------------
def avatar_path(acc_no):
    return os.path.join(AVATAR_DIR, f"{acc_no}.png")


def save_avatar(acc_no, source):
    """Check the chosen photo, crop it to a square and keep a small copy."""
    if not str(acc_no).isdigit():
        return False, "Invalid account"
    if os.path.getsize(source) > MAX_AVATAR_BYTES:
        return False, "Photo is too large. Maximum size is 2 MB"
    os.makedirs(AVATAR_DIR, exist_ok=True)
    if not HAVE_PIL:
        if not source.lower().endswith(".png"):
            return False, "Choose a PNG photo (or run: pip install pillow to use JPG)"
        shutil.copyfile(source, avatar_path(acc_no))
        return True, "Profile photo updated"
    try:
        img = ImageOps.exif_transpose(Image.open(source)).convert("RGB")
    except Exception:
        return False, "This file is not a valid image"
    side = min(img.size)
    left, top = (img.width - side) // 2, (img.height - side) // 2
    img.crop((left, top, left + side, top + side)).resize((256, 256)).save(avatar_path(acc_no), "PNG")
    return True, "Profile photo updated"


def remove_avatar(acc_no):
    try:
        os.remove(avatar_path(acc_no))
    except OSError:
        pass


# =====================================================================
#                              CLASSES
# =====================================================================
class Account:
    """One bank account: data + all money rules."""

    def __init__(self, acc_no, name, username, acc_type, salt, pin_hash,
                 balance=0.0, status="active", history=None,
                 failed_attempts=0, locked_until=0.0, created="",
                 sec_question="", sec_salt="", sec_hash="", payees=None):
        self.acc_no = acc_no
        self.name = name
        self.username = username
        self.acc_type = acc_type
        self.salt = salt
        self.pin_hash = pin_hash
        self.balance = balance
        self.status = status              # "active" or "frozen"
        self.history = history if history is not None else []
        self.failed_attempts = failed_attempts
        self.locked_until = locked_until
        self.created = created
        self.sec_question = sec_question   # security question for forgot PIN
        self.sec_salt = sec_salt
        self.sec_hash = sec_hash
        self.payees = payees if payees is not None else []   # saved receivers (account numbers)

    # ---------- saving / loading ----------
    @classmethod
    def from_dict(cls, acc_no, d):
        return cls(
            acc_no=acc_no,
            name=d.get("name", "Unknown"),
            username=d.get("username", ""),
            acc_type=d.get("acc_type", "Current"),   # old accounts had no type
            salt=d["salt"],
            pin_hash=d["pin_hash"],
            balance=float(d.get("balance", 0)),
            status=d.get("status", "active"),
            history=list(d.get("history", [])),
            failed_attempts=int(d.get("failed_attempts", 0)),
            locked_until=float(d.get("locked_until", 0)),
            created=d.get("created", ""),
            sec_question=d.get("sec_question", ""),
            sec_salt=d.get("sec_salt", ""),
            sec_hash=d.get("sec_hash", ""),
            payees=list(d.get("payees", [])),
        )

    def to_dict(self):
        return {
            "name": self.name,
            "username": self.username,
            "acc_type": self.acc_type,
            "salt": self.salt,
            "pin_hash": self.pin_hash,
            "balance": self.balance,
            "status": self.status,
            "history": self.history,
            "failed_attempts": self.failed_attempts,
            "locked_until": self.locked_until,
            "created": self.created,
            "sec_question": self.sec_question,
            "sec_salt": self.sec_salt,
            "sec_hash": self.sec_hash,
            "payees": self.payees,
        }

    # ---------- PIN security ----------
    def _hash(self, pin):
        return hashlib.pbkdf2_hmac(
            "sha256", pin.encode(), self.salt.encode(), 100_000
        ).hex()

    def set_pin(self, pin):
        self.salt = os.urandom(8).hex()
        self.pin_hash = self._hash(pin)

    def check_pin(self, pin):
        if hmac.compare_digest(self.pin_hash, self._hash(pin)):
            return True
        # accounts made by the older version used a simpler hash
        old = hashlib.sha256((self.salt + pin).encode()).hexdigest()
        if hmac.compare_digest(self.pin_hash, old):
            self.pin_hash = self._hash(pin)   # upgrade silently
            return True
        return False

    def lock_seconds_left(self):
        left = int(self.locked_until - time.time())
        return left if left > 0 else 0

    def register_failure(self):
        self.failed_attempts += 1
        if self.failed_attempts >= MAX_ATTEMPTS:
            self.locked_until = time.time() + LOCK_SECONDS
            self.failed_attempts = 0
            return True       # now locked
        return False

    def unlock(self):
        self.failed_attempts = 0
        self.locked_until = 0.0

    # ---------- security question (forgot PIN) ----------
    def _hash_answer(self, answer):
        cleaned = " ".join(answer.lower().split())
        return hashlib.pbkdf2_hmac(
            "sha256", cleaned.encode(), self.sec_salt.encode(), 100_000
        ).hex()

    def has_security(self):
        return bool(self.sec_question and self.sec_hash)

    def set_security(self, question, answer):
        self.sec_question = question
        self.sec_salt = os.urandom(8).hex()
        self.sec_hash = self._hash_answer(answer)

    def check_answer(self, answer):
        if not self.has_security():
            return False
        return hmac.compare_digest(self.sec_hash, self._hash_answer(answer))

    # ---------- helpers ----------
    def min_balance(self):
        return MIN_BALANCE.get(self.acc_type, 0.0)

    def _log(self, kind, amount, note="", ref=""):
        now = datetime.now()
        ref = ref or new_ref()
        self.history.append({
            "date": now.strftime("%Y-%m-%d"),
            "time": now.strftime("%H:%M:%S"),
            "type": kind,
            "amount": amount,
            "balance": self.balance,
            "note": note,
            "ref": ref,
        })
        return ref

    def today_out(self):
        """Total money that left this account today."""
        today = date.today().isoformat()
        total = 0.0
        for h in self.history:
            if h.get("date") == today and h.get("type") in MONEY_OUT:
                total += h["amount"]
        return round(total, 2)

    def _debit_error(self, amount):
        """Return an error text if this amount cannot leave the account, else None."""
        if self.status != "active":
            return "Account is frozen. Please contact the admin."
        if amount <= 0:
            return "Amount must be greater than 0"
        if amount > self.balance:
            return "Insufficient balance"
        if self.balance - amount < self.min_balance():
            return f"Minimum balance of {money(self.min_balance())} must be maintained"
        remaining = max(DAILY_LIMIT - self.today_out(), 0)
        if amount > remaining:
            return f"Daily limit exceeded. You can still use {money(remaining)} today"
        return None

    # ---------- money operations (each returns (ok, message)) ----------
    def deposit(self, amount):
        amount = round(float(amount), 2)
        if self.status != "active":
            return False, "Account is frozen. Please contact the admin."
        if amount <= 0:
            return False, "Amount must be greater than 0"
        if amount > MAX_DEPOSIT:
            return False, f"Maximum single deposit is {money(MAX_DEPOSIT)}"
        self.balance = round(self.balance + amount, 2)
        ref = self._log("Deposit", amount)
        return True, f"Deposited {money(amount)} · Ref {ref}"

    def withdraw(self, amount):
        amount = round(float(amount), 2)
        error = self._debit_error(amount)
        if error:
            return False, error
        self.balance = round(self.balance - amount, 2)
        ref = self._log("Withdraw", amount)
        return True, f"Withdrew {money(amount)} · Ref {ref}"

    def send(self, other, amount, note=""):
        amount = round(float(amount), 2)
        if other.acc_no == self.acc_no:
            return False, "You cannot transfer to your own account"
        if other.status != "active":
            return False, "Receiver account is frozen"
        error = self._debit_error(amount)
        if error:
            return False, error
        self.balance = round(self.balance - amount, 2)
        other.balance = round(other.balance + amount, 2)
        ref = new_ref()
        self._log("Transfer Out", amount, f"To {other.name} ({other.acc_no}) {note}".strip(), ref)
        other._log("Transfer In", amount, f"From {self.name} ({self.acc_no}) {note}".strip(), ref)
        return True, f"Sent {money(amount)} to {other.name} · Ref {ref}"

    def credit_interest(self, yearly_rate):
        interest = round(self.balance * yearly_rate / 100 / 12, 2)
        if interest > 0:
            self.balance = round(self.balance + interest, 2)
            self._log("Interest", interest, "Monthly interest")
        return interest


class Bank:
    """Holds all accounts, saves them to a file, and handles login rules."""

    def __init__(self, path=DATA_FILE):
        self.path = path
        self.accounts = {}
        self.audit = []
        self.meta = {"admin_failed": 0, "admin_locked_until": 0.0,
                     "last_interest_month": ""}
        self.load()

    # ---------- file handling ----------
    def _read_json(self):
        if not os.path.exists(self.path):
            return {}
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                data = json.load(f)
            return data if isinstance(data, dict) else {}
        except (json.JSONDecodeError, OSError):
            try:   # keep the broken file instead of overwriting it
                os.replace(self.path, self.path + ".corrupt")
            except OSError:
                pass
            return {}

    def load(self):
        data = self._read_json()
        raw = data.get("accounts", data) if "accounts" in data else data
        self.accounts = {}
        for acc_no, d in raw.items():
            if isinstance(d, dict) and "pin_hash" in d:
                self.accounts[acc_no] = Account.from_dict(acc_no, d)
        self.audit = list(data.get("audit", [])) if "accounts" in data else []
        if "accounts" in data:
            self.meta.update(data.get("meta", {}))

    def save(self):
        data = {
            "accounts": {no: a.to_dict() for no, a in self.accounts.items()},
            "audit": self.audit,
            "meta": self.meta,
        }
        tmp = self.path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        os.replace(tmp, self.path)     # safe write: never leaves a half file

    def log(self, who, event):
        self.audit.append({
            "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "who": who,
            "event": event,
        })
        self.audit = self.audit[-500:]

    # ---------- finding accounts ----------
    def find(self, identifier):
        identifier = identifier.strip()
        if identifier in self.accounts:
            return self.accounts[identifier]
        for acc in self.accounts.values():
            if acc.username and acc.username.lower() == identifier.lower():
                return acc
        return None

    # ---------- create / delete ----------
    def create_account(self, name, username, acc_type, pin, confirm_pin, opening,
                       question, answer):
        name = " ".join(name.split())
        username = username.strip()
        opening = round(float(opening), 2)
        if len(name) < 2:
            return False, "Please enter your full name", None
        if not re.fullmatch(r"[A-Za-z0-9_]{3,20}", username):
            return False, "Username must be 3-20 letters, digits or underscore", None
        if username.lower() == "admin" or self.find(username):
            return False, "This username is already taken", None
        if not valid_pin(pin):
            return False, "PIN must be 4 to 8 digits", None
        if pin != confirm_pin:
            return False, "PINs do not match", None
        if question not in SECURITY_QUESTIONS:
            return False, "Please choose a security question", None
        if len(answer.strip()) < 3:
            return False, "Security answer must be at least 3 characters", None
        minimum = MIN_BALANCE[acc_type]
        if opening < minimum:
            return False, f"{acc_type} account needs at least {money(minimum)} to open", None

        while True:
            acc_no = str(random.randint(10000000, 99999999))
            if acc_no not in self.accounts:
                break
        acc = Account(acc_no, name, username, acc_type, "", "",
                      created=datetime.now().strftime("%Y-%m-%d"))
        acc.set_pin(pin)
        acc.set_security(question, answer)
        acc.balance = opening
        if opening > 0:
            acc._log("Opening Deposit", opening)
        self.accounts[acc_no] = acc
        self.log(username, f"Account {acc_no} created ({acc_type})")
        self.save()
        return True, "Account created", acc

    def delete_account(self, acc_no, who):
        acc = self.accounts.pop(acc_no, None)
        remove_avatar(acc_no)
        if acc:
            self.log(who, f"Account {acc_no} ({acc.name}) deleted, balance {money(acc.balance)}")
            self.save()

    # ---------- login rules ----------
    def authenticate(self, identifier, pin):
        generic = "Incorrect username/account number or PIN"
        acc = self.find(identifier)
        if acc is None:
            return None, generic
        left = acc.lock_seconds_left()
        if left:
            return None, f"Too many wrong attempts. Try again in {left // 60 + 1} minute(s)."
        if acc.check_pin(pin):
            acc.unlock()
            self.save()
            return acc, ""
        locked = acc.register_failure()
        if locked:
            self.log("system", f"Account {acc.acc_no} locked after wrong PINs")
        self.save()
        if locked:
            return None, "Too many wrong attempts. Account locked for 5 minutes."
        return None, generic

    def verify_pin(self, acc, pin):
        """Ask for the PIN again before money leaves the account. Wrong PINs count toward the lock."""
        left = acc.lock_seconds_left()
        if left:
            return False, f"Too many wrong attempts. Try again in {left // 60 + 1} minute(s)."
        if acc.check_pin(pin):
            acc.failed_attempts = 0
            return True, ""
        locked = acc.register_failure()
        if locked:
            self.log("system", f"Account {acc.acc_no} locked after wrong PINs (payment)")
        self.save()
        if locked:
            return False, "Too many wrong attempts. Account locked for 5 minutes."
        return False, "Incorrect PIN"

    def reset_pin_with_answer(self, identifier, answer, new_pin, confirm_pin):
        generic = "Details are incorrect. If you did not set a security question, contact the admin."
        acc = self.find(identifier)
        if acc is None or not acc.has_security():
            return False, generic
        left = acc.lock_seconds_left()
        if left:
            return False, f"Too many wrong attempts. Try again in {left // 60 + 1} minute(s)."
        if not acc.check_answer(answer):
            locked = acc.register_failure()
            if locked:
                self.log("system", f"Account {acc.acc_no} locked after wrong security answers")
            self.save()
            if locked:
                return False, "Too many wrong attempts. Account locked for 5 minutes."
            return False, generic
        if not valid_pin(new_pin):
            return False, "PIN must be 4 to 8 digits"
        if new_pin != confirm_pin:
            return False, "PINs do not match"
        acc.set_pin(new_pin)
        acc.unlock()
        self.log(acc.acc_no, "PIN reset using security question")
        self.save()
        return True, "PIN reset done. You can log in with your new PIN now."

    def admin_login(self, password, real_password):
        if not real_password:
            return False, "Admin login is not set up"
        left = int(self.meta["admin_locked_until"] - time.time())
        if left > 0:
            return False, f"Admin login locked. Try again in {left // 60 + 1} minute(s)."
        if hmac.compare_digest(password.encode(), real_password.encode()):
            self.meta["admin_failed"] = 0
            self.log("admin", "Admin logged in")
            self.save()
            return True, ""
        self.meta["admin_failed"] += 1
        if self.meta["admin_failed"] >= MAX_ATTEMPTS:
            self.meta["admin_locked_until"] = time.time() + LOCK_SECONDS
            self.meta["admin_failed"] = 0
            self.log("system", "Admin login locked after wrong passwords")
        self.save()
        return False, "Incorrect admin password"

    # ---------- admin tools ----------
    def total_balance(self):
        total = 0.0
        for acc in self.accounts.values():
            total += acc.balance
        return round(total, 2)

    def apply_interest(self):
        month = datetime.now().strftime("%Y-%m")
        if self.meta["last_interest_month"] == month:
            return False, "Interest for this month was already applied"
        count, total = 0, 0.0
        for acc in self.accounts.values():
            if acc.acc_type == "Savings" and acc.status == "active":
                interest = acc.credit_interest(INTEREST_RATE)
                if interest > 0:
                    count += 1
                    total += interest
        self.meta["last_interest_month"] = month
        self.log("admin", f"Interest applied to {count} accounts, total {money(total)}")
        self.save()
        return True, f"Interest added to {count} Savings accounts (total {money(total)})"

    def export_backup(self):
        return json.dumps({
            "accounts": {no: a.to_dict() for no, a in self.accounts.items()},
            "audit": self.audit,
            "meta": self.meta,
        }, indent=2)

    def restore_backup(self, text):
        try:
            data = json.loads(text)
            raw = data.get("accounts", data)
            restored = {no: Account.from_dict(no, d) for no, d in raw.items()}
        except Exception:
            return False, "This is not a valid backup file"
        self.accounts = restored
        if "accounts" in data:
            self.audit = list(data.get("audit", []))
            self.meta.update(data.get("meta", {}))
        self.log("admin", f"Backup restored ({len(restored)} accounts)")
        self.save()
        return True, f"Restored {len(restored)} accounts"


# =====================================================================
#                      LOOK: colours and drawing helpers
# =====================================================================
LILAC, PURPLE, DEEP = "#c4a8ff", "#7c3aed", "#3b1d6e"
PINK, CORAL, CREAM, SOFT = "#f472b6", "#ff6b81", "#fbf6ff", "#efe4ff"
FONT = "Segoe UI"
W, H = 1040, 700


def mix(c1, c2, t):
    t = max(0.0, min(1.0, t))
    a = [int(c1[i:i + 2], 16) for i in (1, 3, 5)]
    b = [int(c2[i:i + 2], 16) for i in (1, 3, 5)]
    return "#%02x%02x%02x" % tuple(int(a[i] + (b[i] - a[i]) * t) for i in range(3))


def rrect(cv, x1, y1, x2, y2, r, **kw):
    """Rounded rectangle."""
    pts = [x1 + r, y1, x2 - r, y1, x2, y1, x2, y1 + r, x2, y2 - r, x2, y2,
           x2 - r, y2, x1 + r, y2, x1, y2, x1, y2 - r, x1, y1 + r, x1, y1]
    return cv.create_polygon(pts, smooth=True, **kw)


def bubble_image(size, tint):
    """Glass bubble with a real see-through body (needs Pillow): clear middle, soft coloured
    edge, bright rim and two shiny highlights."""
    big = size * 4
    img = Image.new("RGBA", (big, big), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    r, g, b = tint
    half = big // 2
    for i in range(0, half, 2):                      # body: clearer in the middle, denser at the edge
        k = i / half
        alpha = int(6 + 70 * (1 - k) ** 3)
        d.ellipse((i, i, big - 1 - i, big - 1 - i), outline=(r, g, b, alpha), width=2)
    d.ellipse((0, 0, big - 1, big - 1), outline=(255, 255, 255, 185), width=max(3, big // 36))
    d.arc((big * .12, big * .12, big * .88, big * .88), 200, 285, fill=(255, 255, 255, 215), width=max(3, big // 24))
    d.arc((big * .12, big * .12, big * .88, big * .88), 20, 60, fill=(255, 255, 255, 120), width=max(2, big // 40))
    d.ellipse((big * .64, big * .20, big * .74, big * .28), fill=(255, 255, 255, 190))
    return img.resize((size, size), getattr(Image, "Resampling", Image).LANCZOS)


class Pill(tk.Canvas):
    """Glossy 3D-style pill button."""

    def __init__(self, parent, text, command, w=170, h=44, color=PURPLE, fg="white", bg=CREAM, size=11):
        super().__init__(parent, width=w, height=h, bg=bg, highlightthickness=0, cursor="hand2")
        self.cmd, self.color, self.w, self.h, self.text, self.fg, self.size = command, color, w, h, text, fg, size
        self.draw(color)
        self.bind("<Enter>", lambda e: self.draw(mix(self.color, "#ffffff", .18)))
        self.bind("<Leave>", lambda e: self.draw(self.color))
        self.bind("<ButtonPress-1>", lambda e: self.draw(mix(self.color, "#000000", .15)))
        self.bind("<ButtonRelease-1>", self.release)

    def draw(self, col):
        self.delete("all")
        rrect(self, 2, 6, self.w - 2, self.h - 1, self.h // 2, fill=mix(col, "#000000", .22), outline="")
        rrect(self, 2, 2, self.w - 2, self.h - 5, self.h // 2, fill=col, outline="")
        rrect(self, 12, 5, self.w - 12, self.h // 2, self.h // 4, fill=mix(col, "#ffffff", .30), outline="")
        self.create_text(self.w // 2, self.h // 2 - 2, text=self.text, fill=self.fg, font=(FONT, self.size, "bold"))

    def release(self, e):
        self.draw(mix(self.color, "#ffffff", .18))
        if 0 <= e.x <= self.w and 0 <= e.y <= self.h:
            self.cmd()


def label(parent, text, size=10, bold=True, fg=DEEP, **kw):
    return tk.Label(parent, text=text, bg=parent["bg"], fg=fg, anchor="w",
                    font=(FONT, size, "bold" if bold else "normal"), **kw)


def entry(parent, show="", width=26):
    return tk.Entry(parent, show=show, width=width, font=(FONT, 11), relief="flat", bg="white", fg=DEEP,
                    insertbackground=DEEP, highlightthickness=2, highlightbackground="#dccbff", highlightcolor=PURPLE)


class Stage(tk.Canvas):
    """The animated pastel world behind everything."""

    def __init__(self, root):
        super().__init__(root, width=W, height=H, highlightthickness=0, bd=0)
        self.pack()
        self.t = 0.0
        self.planes, self.clouds, self.pills = [], [], []
        self.bubbles, self.bubble_cache = [], {}
        self.ribbon = None
        self._tok = None
        self.build()
        self.animate()

    # ----- scenery -----
    def build(self):
        for y in range(0, H, 4):
            t = y / H
            col = mix("#bda0ff", "#e9d9ff", t / .55) if t < .55 else mix("#e9d9ff", "#fff4fb", (t - .55) / .45)
            self.create_rectangle(0, y, W, y + 4, fill=col, outline=col)
        for k in range(16, 0, -1):                                   # sun glow, top right
            r = 26 * k
            c = mix("#ffffff", "#d9c4ff", (k - 1) / 15)
            self.create_oval(W - 90 - r, 30 - r, W - 90 + r, 30 + r, fill=c, outline="")
        for i in range(26):                                          # halftone dots, bottom left
            for j in range(17):
                r = 3.6 - (i * .11 + j * .17)
                if r > .4:
                    x, y = i * 14 + 8, H - j * 14 - 8
                    self.create_oval(x - r, y - r, x + r, y + r, fill="#a083ee", outline="")
        self.create_arc(-170, -170, 210, 210, start=270, extent=90, style="arc", outline="#ff6fae", width=24)
        self.create_arc(W - 210, H - 210, W + 170, H + 170, start=90, extent=90, style="arc", outline="#ff6fae", width=24)
        for x, y, s in ((120, 90, 1.0), (520, 40, .7), (880, 560, .9), (300, 600, .6)):
            ids = [self.create_oval(x + dx * s, y + dy * s, x + (dx + w) * s, y + (dy + h) * s, fill="white", outline="")
                   for dx, dy, w, h in ((0, 20, 90, 40), (25, 0, 60, 50), (60, 12, 70, 44), (-10, 28, 50, 28))]
            self.clouds.append([ids, .25 + s * .2])
        for x, y, s, c in ((470, 120, 1.0, PURPLE), (880, 230, .8, PINK), (60, 380, .7, "#9d7bff")):
            a = self.create_polygon([x, y + 10 * s, x + 70 * s, y, x + 28 * s, y + 26 * s], fill=mix(c, "#ffffff", .35), outline="")
            b = self.create_polygon([x + 28 * s, y + 26 * s, x + 70 * s, y, x + 36 * s, y + 48 * s], fill=c, outline="")
            self.planes.append([[a, b], 0.0, 0.0, random.random() * 6, .7 + random.random() * .6])
        for x, y, w, c in ((420, 640, 70, CORAL), (200, 60, 46, PINK), (960, 120, 54, "#a68bff")):
            self.pills.append([rrect(self, x, y, x + w, y + w // 2, w // 4, fill=c, outline="white", width=2), 0.0, random.random() * 6])
        for size in (96, 76, 62, 52, 44, 38, 32, 28, 24, 70, 46, 34, 58, 30):   # floating glass bubbles
            self.spawn_bubble(size, random.randint(20, W - 20), random.randint(0, H))
        self.tag_bind("bubble", "<Button-1>", self.pop_bubble)
        self.ribbon = self.create_line(0, 0, 1, 1, width=7, fill="#ff5d73", smooth=True, capstyle="round")

    def animate(self):
        self.t += .035
        for ids, sp in self.clouds:
            for i in ids:
                self.move(i, sp, 0)
            if self.coords(ids[0])[0] > W + 20:
                for i in ids:
                    self.move(i, -(W + 260), 0)
        for p in self.planes:
            ox, oy = 14 * math.sin(self.t * p[4] + p[3]), 10 * math.cos(self.t * p[4] * 1.3 + p[3])
            for i in p[0]:
                self.move(i, ox - p[1], oy - p[2])
            p[1], p[2] = ox, oy
        for p in self.pills:
            oy = 8 * math.sin(self.t * 1.2 + p[2])
            self.move(p[0], 0, oy - p[1])
            p[1] = oy
        for b in self.bubbles:                      # glass bubbles drift up and sway
            item, size, phase, speed = b
            self.move(item, .7 * math.sin(self.t * .8 + phase), -speed)
            x1, y1, x2, y2 = self.bbox(item)
            if y2 < 0:
                self.respawn(item, size)
        pts = []
        for x in range(-20, W + 60, 40):
            pts += [x, H - 60 + 26 * math.sin(x / 95 + self.t) + 10 * math.sin(x / 40 - self.t * 1.7)]
        self.coords(self.ribbon, *pts)
        self.after(40, self.animate)

    # ----- glass bubbles -----
    def spawn_bubble(self, size, x, y):
        tint = random.choice(((196, 168, 255), (244, 114, 182), (255, 255, 255), (150, 190, 255)))
        if HAVE_PIL:                                       # real transparency
            key = (size, tint)
            if key not in self.bubble_cache:
                self.bubble_cache[key] = ImageTk.PhotoImage(bubble_image(size, tint))
            item = self.create_image(x, y, image=self.bubble_cache[key], tags="bubble")
        else:                                              # no Pillow: stippled "see-through" look
            r = size // 2
            item = self.create_oval(x - r, y - r, x + r, y + r, fill=mix("#ffffff", "#c4a8ff", random.random()),
                                    stipple="gray25", outline="white", width=2, tags="bubble")
        self.bubbles.append([item, size, random.random() * 6, .25 + random.random() * .55])

    def respawn(self, item, size):
        x1, y1, x2, y2 = self.bbox(item)
        self.move(item, random.randint(20, W - 20) - (x1 + x2) / 2, H + size - y1)

    def pop_bubble(self, _e):
        found = self.find_withtag("current")
        for b in self.bubbles:
            if found and b[0] == found[0]:
                x1, y1, x2, y2 = self.bbox(b[0])
                self.respawn(b[0], b[1])
                self.burst((x1 + x2) / 2, (y1 + y2) / 2, (x2 - x1) / 2, 0)
                return

    def burst(self, cx, cy, r, n, ring=None):
        if ring is None:
            ring = self.create_oval(cx - r, cy - r, cx + r, cy + r, outline="white", width=3)
        if n > 7:
            self.delete(ring)
            return
        r2 = r + n * 4
        self.coords(ring, cx - r2, cy - r2, cx + r2, cy + r2)
        self.itemconfig(ring, width=max(1, 3 - n // 3))
        self.after(24, lambda: self.burst(cx, cy, r, n + 1, ring))

    # ----- motion helpers -----
    def kinetic(self, text, x, y, size, tag, delay=0):
        """Big title whose letters rise up and fade in, one after another."""
        f = tkfont.Font(family=FONT, size=size, weight="bold")
        cx = x
        for i, ch in enumerate(text):
            sh = self.create_text(cx + 4, y + 75, text=ch, anchor="w", font=f, fill="#a98af0", tags=tag)
            tx = self.create_text(cx, y + 70, text=ch, anchor="w", font=f, fill="#d9c8ff", tags=tag)
            self.after(delay + i * 70, lambda s=sh, t=tx: self.rise(s, t, 0))
            cx += f.measure(ch)

    def rise(self, sh, tx, n):
        if n > 12:
            return
        e = lambda k: 70 * (1 - (1 - k / 12) ** 3)
        d = e(n) - e(n - 1) if n else 0
        self.move(sh, 0, -d)
        self.move(tx, 0, -d)
        self.itemconfig(tx, fill=mix("#d9c8ff", "#ffffff", n / 12))
        self.after(28, lambda: self.rise(sh, tx, n + 1))

    def reveal(self):
        """Slide the cards up into place."""
        self.move("card", 0, 40)
        self.move("ui", 0, 40)
        self.slide(0)

    def slide(self, n):
        if n < 10:
            self.move("card", 0, -4)
            self.move("ui", 0, -4)
            self.after(18, lambda: self.slide(n + 1))

    def toast(self, msg, ok=True):
        self.delete("toast")
        col = PURPLE if ok else "#e11d48"
        w = max(280, len(msg) * 8 + 60)
        x = W // 2
        rrect(self, x - w // 2, -60, x + w // 2, -14, 23, fill=col, outline="white", width=2, tags="toast")
        self.create_text(x, -37, text=msg, fill="white", font=(FONT, 11, "bold"), tags="toast")
        tok = object()
        self._tok = tok
        self.drop(0)
        self.after(3400, lambda: self.delete("toast") if self._tok is tok else None)

    def drop(self, n):
        if n < 8:
            self.move("toast", 0, 10)
            self.tag_raise("toast")
            self.after(16, lambda: self.drop(n + 1))


class BubbleCursor:
    """A glass bubble that follows the mouse pointer (Windows).
    The window is see-through (colour key) and the middle of the bubble is empty, so every click
    goes straight to the button underneath. On Mac / Linux, where see-through windows are not
    available, it quietly switches itself off and the normal cursor is used."""
    S, R, KEY = 88, 20, "#010203"
    OFFSET = (5, 8)           # the bubble sits a little down-right, so the arrow is inside it

    def __init__(self, root):
        self.root, self.win, self.shown = root, None, False
        self.t, self.n, self.pop, self.down, self.last = 0.0, 0, 0, False, None
        win = None
        try:
            win = tk.Toplevel(root)
            win.withdraw()
            win.overrideredirect(True)
            win.config(bg=self.KEY)
            win.attributes("-topmost", True)
            win.attributes("-transparentcolor", self.KEY)
            win.attributes("-alpha", 0.9)
        except tk.TclError:
            if win is not None:
                win.destroy()
            return
        self.win = win
        self.cv = tk.Canvas(win, width=self.S, height=self.S, bg=self.KEY, highlightthickness=0, bd=0)
        self.cv.pack()
        root.bind_all("<ButtonPress-1>", self.press, add="+")
        root.bind_all("<ButtonRelease-1>", self.release, add="+")
        self.tick()

    def press(self, _e):
        self.down, self.pop = True, 8

    def release(self, _e):
        self.down = False

    def tick(self):
        r = self.root
        try:
            px, py = r.winfo_pointerxy()
            rx, ry = r.winfo_rootx(), r.winfo_rooty()
            inside = rx <= px < rx + r.winfo_width() and ry <= py < ry + r.winfo_height()
            focused = bool(str(r.tk.call("focus", "-displayof", ".")))
            want = inside and focused and r.state() == "normal"
            if want != self.shown:
                self.win.deiconify() if want else self.win.withdraw()
                self.shown, self.last = want, None
            if want:
                if (px, py) != self.last:
                    x = px + self.OFFSET[0] - self.S // 2
                    y = py + self.OFFSET[1] - self.S // 2
                    self.win.geometry(f"{self.S}x{self.S}{x:+d}{y:+d}")
                    self.last = (px, py)
                self.t += .1
                self.n += 1
                if self.n % 3 == 0 or self.pop:
                    self.draw()
        except tk.TclError:
            return                                   # the window was closed
        r.after(16, self.tick)

    def draw(self):
        c, mid = self.cv, self.S // 2
        c.delete("all")
        r = self.R + 1.2 * math.sin(self.t) - (3 if self.down else 0)
        rim = PINK if self.down else "#b79bff"
        box = lambda rad: (mid - rad, mid - rad, mid + rad, mid + rad)
        c.create_oval(*box(r + 2), outline=rim, width=2)                        # coloured outer edge
        c.create_oval(*box(r), outline="white", width=2)                        # bright rim
        c.create_arc(*box(r - 4), start=105, extent=60, style="arc", outline="white", width=3)   # shine
        c.create_oval(mid + r * .55 - 2, mid - r * .62 - 2, mid + r * .55 + 2, mid - r * .62 + 2,
                      fill="white", outline="white")                            # sparkle
        if self.pop:                                                            # ring that grows on click
            k = 8 - self.pop
            c.create_oval(*box(r + 4 + k * 2.4), outline=PINK if self.down else LILAC, width=max(1, 3 - k // 3))
            self.pop -= 1


# =====================================================================
#                              THE APP
# =====================================================================
NAV = [("overview", "Overview"), ("deposit", "Deposit"), ("withdraw", "Withdraw"),
       ("transfer", "Transfer"), ("statement", "Statement"), ("profile", "Profile & settings")]


class Nav(tk.Label):
    def __init__(self, parent, text, command, active=False):
        super().__init__(parent, text="  " + text, anchor="w", cursor="hand2", font=(FONT, 12, "bold"),
                         bg=SOFT if active else CREAM, fg=PURPLE if active else DEEP, pady=9)
        self.base = self["bg"]
        self.bind("<Enter>", lambda e: self.config(bg=SOFT))
        self.bind("<Leave>", lambda e: self.config(bg=self.base))
        self.bind("<Button-1>", lambda e: command())


class App:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("NovaVault Bank")
        sw, sh = self.root.winfo_screenwidth(), self.root.winfo_screenheight()
        self.root.geometry(f"{W}x{H}+{max((sw - W) // 2, 0)}+{max((sh - H) // 2 - 20, 0)}")
        self.root.resizable(False, False)
        self.bank = Bank()
        self.stage = Stage(self.root)
        self.frames, self.imgs = [], []
        self.user, self.view, self.hide, self.admin = None, "overview", False, False
        self.last = time.time()
        style = ttk.Style()
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        style.configure("Treeview", background="white", fieldbackground="white", foreground=DEEP, rowheight=27, font=(FONT, 10))
        style.configure("Treeview.Heading", background=SOFT, foreground=DEEP, font=(FONT, 10, "bold"), relief="flat")
        style.map("Treeview", background=[("selected", LILAC)], foreground=[("selected", DEEP)])
        style.configure("TNotebook", background=CREAM, borderwidth=0)
        style.configure("TNotebook.Tab", font=(FONT, 10, "bold"), padding=(12, 6))
        self.root.bind_all("<Key>", self.touch)
        self.root.bind_all("<Button>", self.touch)
        self.root.after(5000, self.check_timeout)
        self.show_auth()
        self.cursor = BubbleCursor(self.root)

    def run(self):
        self.root.mainloop()

    # ----- plumbing -----
    def touch(self, _e=None):
        self.last = time.time()

    def check_timeout(self):
        if (self.user or self.admin) and time.time() - self.last > SESSION_TIMEOUT:
            self.logout("You were logged out after 10 minutes of inactivity")
        self.root.after(5000, self.check_timeout)

    def clear(self):
        for fr in self.frames:
            try:
                fr.destroy()
            except Exception:
                pass
        self.frames, self.imgs = [], []
        for tag in ("card", "ui", "title"):
            self.stage.delete(tag)

    def card(self, x, y, w, h, pad=22):
        s = self.stage
        rrect(s, x + 4, y + 10, x + w + 4, y + h + 10, 30, fill=mix(SOFT, "#6d4bc2", .22), outline="", tags="card")
        rrect(s, x, y, x + w, y + h, 30, fill=CREAM, outline="white", width=3, tags="card")
        fr = tk.Frame(s, bg=CREAM)
        self.frames.append(fr)
        s.create_window(x + pad, y + pad, window=fr, anchor="nw", width=w - 2 * pad, height=h - 2 * pad, tags="ui")
        return fr

    def acc(self):
        return self.bank.accounts.get(self.user)

    def logout(self, message="Logged out. See you soon!"):
        self.user = None
        self.show_auth()
        self.stage.toast(message, True)

    def finish(self, result, view=None):
        ok, message = result[0], result[1]
        if ok:
            self.bank.save()
        self.stage.toast(message, ok)
        if ok:
            self.show_user(view or self.view)
        return ok

    def pin_ok(self, acc, pin):
        ok, message = self.bank.verify_pin(acc, pin)
        if not ok:
            self.stage.toast(message, False)
        return ok

    def table(self, parent, cols, widths, height=8):
        t = ttk.Treeview(parent, columns=cols, show="headings", height=height)
        for c, w in zip(cols, widths):
            t.heading(c, text=c)
            t.column(c, width=w, anchor="w")
        return t

    def avatar(self, parent, acc, size):
        c = tk.Canvas(parent, width=size, height=size, bg=parent["bg"], highlightthickness=0)
        path = avatar_path(acc.acc_no)
        photo = None
        try:
            if os.path.exists(path):
                if HAVE_PIL:
                    img = Image.open(path).convert("RGBA").resize((size, size))
                    mask = Image.new("L", (size, size), 0)
                    ImageDraw.Draw(mask).ellipse((0, 0, size - 1, size - 1), fill=255)
                    img.putalpha(mask)
                    photo = ImageTk.PhotoImage(img)
                else:
                    photo = tk.PhotoImage(file=path)
                    photo = photo.subsample(max(1, photo.width() // size))
        except Exception:
            photo = None
        c.create_oval(1, 1, size - 1, size - 1, fill=PURPLE, outline="white", width=3)
        if photo is not None:
            self.imgs.append(photo)
            c.create_image(size // 2, size // 2, image=photo)
        else:
            c.create_text(size // 2, size // 2, text=(acc.name.strip()[:1] or "?").upper(), fill="white",
                          font=(FONT, size // 2, "bold"))
        return c

    # ----- login / create / forgot -----
    def show_auth(self, tab="login"):
        self.clear()
        self.admin = False
        s = self.stage
        s.kinetic("Nova", 70, 150, 78, "title")
        s.kinetic("Vault", 70, 255, 78, "title", delay=350)
        s.create_text(74, 340, anchor="nw", text="Your money. Your vault.\nYour rules.", font=(FONT, 20), fill=DEEP, tags="title")
        for i, t in enumerate(("Hashed PIN", "Instant transfers", f"{INTEREST_RATE}% interest")):
            x = 74 + i * 150
            rrect(s, x, 440, x + 138, 478, 19, fill="white", outline="#dccbff", width=2, tags="title")
            s.create_text(x + 69, 459, text=t, fill=PURPLE, font=(FONT, 10, "bold"), tags="title")
        fr = self.card(590, 40, 410, 620)
        bar = tk.Frame(fr, bg=CREAM)
        bar.pack(fill="x", pady=(0, 10))
        for key, text in (("login", "Log in"), ("create", "Sign up"), ("forgot", "Forgot PIN")):
            Pill(bar, text, lambda k=key: self.show_auth(k), w=114, h=38, size=10,
                 color=PURPLE if key == tab else "#cdb6ff").pack(side="left", padx=2)
        body = tk.Frame(fr, bg=CREAM)
        body.pack(fill="both", expand=True)
        getattr(self, "auth_" + tab)(body)
        s.reveal()

    def field(self, parent, row, col, text, show="", span=1, width=26):
        label(parent, text).grid(row=row * 2, column=col, columnspan=span, sticky="w", pady=(8, 2))
        e = entry(parent, show, width)
        e.grid(row=row * 2 + 1, column=col, columnspan=span, sticky="ew", padx=(0, 6 if span == 1 and col == 0 else 0), ipady=5)
        return e

    def auth_login(self, body):
        body.columnconfigure(0, weight=1)
        who = self.field(body, 0, 0, "Username or account number")
        pin = self.field(body, 1, 0, "PIN", "\u2022")
        def go():
            acc, message = self.bank.authenticate(who.get(), pin.get())
            if acc is None:
                self.stage.toast(message, False)
                return
            self.user, self.view, self.last = acc.acc_no, "overview", time.time()
            self.show_user("overview")
            self.stage.toast(f"Welcome back, {acc.name.split()[0]}!", True)
        pin.bind("<Return>", lambda e: go())
        Pill(body, "Log in", go, w=360, h=50, size=13).grid(row=4, column=0, pady=(24, 10))
        lk = tk.Label(body, text="Admin login", bg=CREAM, fg=PURPLE, cursor="hand2", font=(FONT, 10, "underline"))
        lk.grid(row=5, column=0)
        lk.bind("<Button-1>", lambda e: self.admin_login())

    def auth_create(self, body):
        body.columnconfigure((0, 1), weight=1)
        name = self.field(body, 0, 0, "Full name", span=2)
        user = self.field(body, 1, 0, "Username", span=2)
        label(body, "Account type").grid(row=4, column=0, sticky="w", pady=(8, 2))
        typ = ttk.Combobox(body, values=("Savings", "Current"), state="readonly", width=12)
        typ.set("Savings")
        typ.grid(row=5, column=0, sticky="ew", padx=(0, 6), ipady=3)
        opening = self.field(body, 2, 1, "Opening deposit", width=12)
        pin = self.field(body, 3, 0, "PIN (4-8 digits)", "\u2022", width=12)
        conf = self.field(body, 3, 1, "Confirm PIN", "\u2022", width=12)
        label(body, "Security question").grid(row=8, column=0, columnspan=2, sticky="w", pady=(8, 2))
        q = ttk.Combobox(body, values=SECURITY_QUESTIONS, state="readonly")
        q.grid(row=9, column=0, columnspan=2, sticky="ew", ipady=3)
        ans = self.field(body, 5, 0, "Answer", span=2)
        def go():
            amount = to_float(opening.get())
            if amount is None:
                self.stage.toast("Enter the opening deposit as a number", False)
                return
            ok, message, acc = self.bank.create_account(name.get(), user.get(), typ.get(), pin.get(), conf.get(),
                                                         amount, q.get(), ans.get())
            self.stage.toast(message, ok)
            if ok:
                messagebox.showinfo("Account created", f"Your account number is {acc.acc_no}.\nKeep it safe.")
                self.show_auth("login")
        Pill(body, "Create account", go, w=360, h=48, size=12).grid(row=12, column=0, columnspan=2, pady=(18, 0))

    def auth_forgot(self, body):
        body.columnconfigure(0, weight=1)
        who = self.field(body, 0, 0, "Username or account number")
        qlab = label(body, "", size=10, fg=PURPLE, wraplength=350, justify="left")
        qlab.grid(row=3, column=0, sticky="w", pady=(10, 0))
        def show_q():
            acc = self.bank.find(who.get())
            if acc is None or not acc.has_security():
                self.stage.toast("Details are incorrect. Contact the admin if you set no question.", False)
            else:
                qlab.config(text="Security question: " + acc.sec_question)
        Pill(body, "Show my question", show_q, w=190, h=36, size=10, color="#a68bff").grid(row=2, column=0, sticky="w", pady=(10, 0))
        ans = self.field(body, 2, 0, "Answer")
        pin = self.field(body, 3, 0, "New PIN (4-8 digits)", "\u2022")
        conf = self.field(body, 4, 0, "Confirm new PIN", "\u2022")
        def go():
            ok, message = self.bank.reset_pin_with_answer(who.get(), ans.get(), pin.get(), conf.get())
            self.stage.toast(message, ok)
            if ok:
                self.bank.save()
                self.show_auth("login")
        Pill(body, "Reset PIN", go, w=360, h=48, size=12).grid(row=10, column=0, pady=(18, 0))

    # ----- user screens -----
    def show_user(self, view="overview"):
        acc = self.acc()
        if acc is None:
            self.logout("This account no longer exists")
            return
        self.clear()
        self.view = view
        side = self.card(30, 40, 240, 620, pad=18)
        self.avatar(side, acc, 86).pack(pady=(4, 6))
        label(side, acc.name, size=14).pack(fill="x")
        label(side, f"A/C {acc.acc_no}", size=9, bold=False, fg="#7a5fc0").pack(fill="x", pady=(0, 14))
        for key, text in NAV:
            Nav(side, text, lambda k=key: self.show_user(k), active=key == view).pack(fill="x", pady=2)
        Pill(side, "Log out", self.logout, w=196, color=CORAL).pack(side="bottom", pady=6)
        main = self.card(290, 40, 720, 620, pad=26)
        head = tk.Frame(main, bg=CREAM)
        head.pack(fill="x")
        label(head, f"Hi, {acc.name.split()[0]}", size=26).pack(side="left")
        label(head, datetime.now().strftime("%A, %d %B"), size=10, bold=False, fg="#7a5fc0").pack(side="right", pady=12)
        if acc.status != "active":
            label(main, "Your account is frozen. Please contact the admin.", fg="#e11d48").pack(fill="x")
        body = tk.Frame(main, bg=CREAM)
        body.pack(fill="both", expand=True, pady=(8, 0))
        {"overview": self.v_overview, "deposit": lambda b, a: self.v_money(b, a, "Deposit"),
         "withdraw": lambda b, a: self.v_money(b, a, "Withdraw"), "transfer": self.v_transfer,
         "statement": self.v_statement, "profile": self.v_profile}[view](body, acc)
        self.stage.reveal()

    def v_overview(self, body, acc):
        c = tk.Canvas(body, width=664, height=184, bg=CREAM, highlightthickness=0)
        c.pack(pady=(0, 10))
        frozen = acc.status != "active"
        base = "#8a94a8" if frozen else PURPLE
        rrect(c, 4, 10, 664, 184, 28, fill=mix(base, "#000000", .25), outline="")
        rrect(c, 0, 0, 660, 176, 28, fill=base, outline="")
        rrect(c, 12, 8, 648, 86, 22, fill=mix(base, "#ffffff", .13), outline="")
        rrect(c, 34, 50, 82, 80, 7, fill="#f6c453", outline="#b9892b")
        c.create_text(34, 28, anchor="w", fill="#eadfff", font=(FONT, 10, "bold"),
                      text=f"{acc.acc_type.upper()} ACCOUNT   \u2022   {'FROZEN' if frozen else 'ACTIVE'}")
        c.create_text(34, 118, anchor="w", fill="white", font=(FONT, 30, "bold"),
                      text="\u20b9 \u2022\u2022\u2022\u2022\u2022\u2022" if self.hide else money(acc.balance))
        eye = c.create_text(626, 28, anchor="e", text="Show" if self.hide else "Hide", fill="white", font=(FONT, 10, "underline"))
        c.tag_bind(eye, "<Button-1>", lambda e: self.toggle_hide())
        c.create_text(34, 150, anchor="w", fill="#eadfff", font=(FONT, 8, "bold"), text="ACCOUNT NO.")
        c.create_text(120, 150, anchor="w", fill="white", font=(FONT, 11, "bold"), text=f"{acc.acc_no[:4]} {acc.acc_no[4:]}")
        c.create_text(626, 150, anchor="e", fill="white", font=(FONT, 11, "bold"), text=acc.name.upper()[:24])
        row = tk.Frame(body, bg=CREAM)
        row.pack(fill="x", pady=(0, 8))
        extra = ("Interest next month", money(round(acc.balance * INTEREST_RATE / 100 / 12, 2))) if acc.acc_type == "Savings" \
            else ("Minimum balance", money(acc.min_balance()))
        for t, v in (("Daily limit left", money(max(DAILY_LIMIT - acc.today_out(), 0))), ("Spent today", money(acc.today_out())), extra):
            box = tk.Frame(row, bg=SOFT, padx=14, pady=8)
            box.pack(side="left", expand=True, fill="x", padx=3)
            label(box, t, size=9, bold=False, fg="#7a5fc0").pack(fill="x")
            label(box, v, size=13).pack(fill="x")
        label(body, "Recent transactions", size=12).pack(fill="x", pady=(8, 4))
        tree = self.table(body, ("Date", "Type", "Amount", "Balance", "Ref"), (110, 130, 120, 130, 140), 6)
        tree.pack(fill="x")
        for h in list(reversed(acc.history))[:6]:
            tree.insert("", "end", values=(h.get("date", "-"), h.get("type", ""), f"{h.get('amount', 0):,.2f}",
                                           f"{h.get('balance', 0):,.2f}", h.get("ref", "-")))

    def toggle_hide(self):
        self.hide = not self.hide
        self.show_user("overview")

    def v_money(self, body, acc, kind):
        label(body, kind, size=20).pack(fill="x", pady=(6, 0))
        note = f"Maximum single deposit {money(MAX_DEPOSIT)}" if kind == "Deposit" else \
            f"Minimum balance {money(acc.min_balance())}  \u2022  Daily limit left {money(max(DAILY_LIMIT - acc.today_out(), 0))}"
        label(body, note, size=10, bold=False, fg="#7a5fc0").pack(fill="x", pady=(0, 10))
        label(body, "Amount (\u20b9)").pack(fill="x")
        amt = entry(body, width=34)
        amt.pack(anchor="w", ipady=6, pady=(2, 10))
        label(body, "PIN to confirm").pack(fill="x")
        pin = entry(body, "\u2022", 34)
        pin.pack(anchor="w", ipady=6, pady=(2, 18))
        def go():
            amount = to_float(amt.get())
            if amount is None:
                self.stage.toast("Enter the amount as a number", False)
            elif self.pin_ok(acc, pin.get()):
                self.finish(acc.deposit(amount) if kind == "Deposit" else acc.withdraw(amount))
        Pill(body, kind, go, w=250, h=50, size=13).pack(anchor="w")

    def v_transfer(self, body, acc):
        label(body, "Send money", size=20).pack(fill="x", pady=(6, 6))
        saved = [no for no in acc.payees if no in self.bank.accounts]
        label(body, "Receiver (username, account number or saved payee)").pack(fill="x")
        who = ttk.Combobox(body, values=[f"{self.bank.accounts[no].name} ({no})" for no in saved], width=44)
        who.pack(anchor="w", ipady=4, pady=(2, 8))
        label(body, "Amount (\u20b9)").pack(fill="x")
        amt = entry(body, width=34)
        amt.pack(anchor="w", ipady=5, pady=(2, 8))
        label(body, "Note (optional)").pack(fill="x")
        note = entry(body, width=34)
        note.pack(anchor="w", ipady=5, pady=(2, 8))
        label(body, "PIN to confirm").pack(fill="x")
        pin = entry(body, "\u2022", 34)
        pin.pack(anchor="w", ipady=5, pady=(2, 14))
        def go():
            text = who.get().strip()
            m = re.search(r"\((\d+)\)$", text)
            target = self.bank.find(m.group(1) if m else text)
            amount = to_float(amt.get())
            if target is None:
                self.stage.toast("Receiver not found", False)
            elif amount is None:
                self.stage.toast("Enter the amount as a number", False)
            elif self.pin_ok(acc, pin.get()):
                if self.finish(acc.send(target, amount, note.get().strip()[:40]), "transfer") and target.acc_no not in acc.payees:
                    if messagebox.askyesno("Save payee", f"Save {target.name} as a payee for next time?"):
                        acc.payees.append(target.acc_no)
                        self.bank.save()
        Pill(body, "Send money", go, w=250, h=50, size=13).pack(anchor="w")

    def v_statement(self, body, acc):
        bar = tk.Frame(body, bg=CREAM)
        bar.pack(fill="x", pady=(4, 6))
        kinds = ["All"] + sorted({h.get("type", "") for h in acc.history})
        label(bar, "Type").grid(row=0, column=0, sticky="w")
        typ = ttk.Combobox(bar, values=kinds, state="readonly", width=15)
        typ.set("All")
        typ.grid(row=1, column=0, padx=(0, 8), ipady=3)
        label(bar, "From (YYYY-MM-DD)").grid(row=0, column=1, sticky="w")
        d1 = entry(bar, width=14)
        d1.grid(row=1, column=1, padx=(0, 8), ipady=4)
        label(bar, "To").grid(row=0, column=2, sticky="w")
        d2 = entry(bar, width=14)
        d2.grid(row=1, column=2, padx=(0, 8), ipady=4)
        tree = self.table(body, ("Date", "Time", "Type", "Amount", "Balance", "Ref"), (90, 80, 120, 110, 120, 130), 12)
        info = label(body, "", size=10, fg="#7a5fc0")
        shown = []
        def refresh():
            for box in (d1, d2):
                text = box.get().strip()
                if text:
                    try:
                        datetime.strptime(text, "%Y-%m-%d")
                    except ValueError:
                        self.stage.toast("Dates must look like 2026-11-23", False)
                        return
            shown.clear()
            for h in acc.history:
                day = h.get("date", "")
                if typ.get() not in ("All", h.get("type", "")) or (d1.get().strip() and day < d1.get().strip()) \
                        or (d2.get().strip() and day > d2.get().strip()):
                    continue
                shown.append(h)
            tree.delete(*tree.get_children())
            for h in reversed(shown):
                tree.insert("", "end", values=(h.get("date", "-"), h.get("time", "-"), h.get("type", ""),
                                               f"{h.get('amount', 0):,.2f}", f"{h.get('balance', 0):,.2f}", h.get("ref", "-")))
            tin = sum(h["amount"] for h in shown if h.get("type") in MONEY_IN)
            tout = sum(h["amount"] for h in shown if h.get("type") in MONEY_OUT)
            info.config(text=f"{len(shown)} transactions   \u2022   Money in {money(tin)}   \u2022   Money out {money(tout)}")
        def export():
            path = filedialog.asksaveasfilename(defaultextension=".csv", initialfile=f"statement_{acc.acc_no}.csv",
                                                filetypes=[("CSV file", "*.csv")])
            if path:
                with open(path, "w", newline="", encoding="utf-8") as f:
                    w = csv.writer(f)
                    w.writerow(["Date", "Time", "Type", "Amount", "Balance", "Note", "Ref"])
                    for h in shown:
                        w.writerow([h.get("date", ""), h.get("time", ""), h.get("type", ""), h.get("amount", 0),
                                    h.get("balance", 0), h.get("note", ""), h.get("ref", "")])
                self.stage.toast("Statement saved", True)
        Pill(bar, "Show", refresh, w=90, h=38, size=10).grid(row=1, column=3, padx=4)
        Pill(bar, "Save CSV", export, w=110, h=38, size=10, color=PINK).grid(row=1, column=4)
        tree.pack(fill="both", expand=True)
        info.pack(fill="x", pady=(6, 0))
        refresh()

    def v_profile(self, body, acc):
        nb = ttk.Notebook(body)
        nb.pack(fill="both", expand=True)
        def tab(name):
            f = tk.Frame(nb, bg=CREAM, padx=14, pady=12)
            nb.add(f, text=name)
            return f
        t = tab("Details")
        self.avatar(t, acc, 96).grid(row=0, column=0, rowspan=4, padx=(0, 18), sticky="n")
        for i, (k, v) in enumerate((("Name", acc.name), ("Username", acc.username or "-"), ("Account number", acc.acc_no),
                                    ("Type", acc.acc_type), ("Opened on", acc.created or "-"), ("Status", acc.status.title()))):
            label(t, f"{k}:  {v}", size=11, bold=False).grid(row=i, column=1, sticky="w", pady=1)
        def pick():
            path = filedialog.askopenfilename(filetypes=[("Images", "*.png *.jpg *.jpeg"), ("All files", "*.*")])
            if path:
                self.finish(save_avatar(acc.acc_no, path), "profile")
        def drop():
            remove_avatar(acc.acc_no)
            self.finish((True, "Profile photo removed"), "profile")
        Pill(t, "Change photo", pick, w=170, h=40, size=10).grid(row=7, column=0, columnspan=2, sticky="w", pady=(18, 0))
        if os.path.exists(avatar_path(acc.acc_no)):
            Pill(t, "Remove photo", drop, w=170, h=40, size=10, color=CORAL).grid(row=8, column=0, columnspan=2, sticky="w", pady=6)
        t = tab("Change PIN")
        old, new, conf = (self.field(t, i, 0, txt, "\u2022", width=30) for i, txt in
                          enumerate(("Current PIN", "New PIN (4-8 digits)", "Confirm new PIN")))
        def change():
            if not self.pin_ok(acc, old.get()):
                return
            if not valid_pin(new.get()):
                self.stage.toast("PIN must be 4 to 8 digits", False)
            elif new.get() != conf.get():
                self.stage.toast("PINs do not match", False)
            else:
                acc.set_pin(new.get())
                self.bank.log(acc.acc_no, "PIN changed")
                self.finish((True, "PIN changed"), "profile")
        Pill(t, "Change PIN", change, w=200, h=44).grid(row=8, column=0, sticky="w", pady=16)
        t = tab("Security question")
        label(t, "Used to reset your PIN if you forget it.", bold=False).grid(row=0, column=0, sticky="w")
        q = ttk.Combobox(t, values=SECURITY_QUESTIONS, state="readonly", width=40)
        q.grid(row=1, column=0, sticky="w", ipady=3, pady=6)
        ans = self.field(t, 1, 0, "Answer", width=30)
        pin = self.field(t, 2, 0, "PIN to confirm", "\u2022", width=30)
        def setq():
            if not q.get() or len(ans.get().strip()) < 3:
                self.stage.toast("Choose a question and an answer of 3+ characters", False)
            elif self.pin_ok(acc, pin.get()):
                acc.set_security(q.get(), ans.get())
                self.bank.log(acc.acc_no, "Security question updated")
                self.finish((True, "Security question saved"), "profile")
        Pill(t, "Save", setq, w=160, h=44).grid(row=8, column=0, sticky="w", pady=14)
        t = tab("Payees")
        saved = [no for no in acc.payees if no in self.bank.accounts]
        lb = tk.Listbox(t, height=7, width=46, font=(FONT, 11), relief="flat", highlightthickness=2, highlightbackground="#dccbff")
        for no in saved:
            lb.insert("end", f"{self.bank.accounts[no].name} ({no})")
        lb.pack(anchor="w")
        def remove():
            if lb.curselection():
                acc.payees.remove(saved[lb.curselection()[0]])
                self.finish((True, "Payee removed"), "profile")
        Pill(t, "Remove selected", remove, w=190, h=40, size=10, color=CORAL).pack(anchor="w", pady=10)
        t = tab("Close account")
        label(t, f"Closing pays out your remaining balance ({money(acc.balance)}) and cannot be undone.",
              fg="#e11d48", wraplength=560, justify="left").pack(fill="x", pady=(0, 10))
        pin = entry(t, "\u2022", 30)
        label(t, "PIN to confirm").pack(anchor="w")
        pin.pack(anchor="w", ipady=5, pady=(2, 12))
        def close():
            if self.pin_ok(acc, pin.get()) and messagebox.askyesno("Close account", "Really close your account?"):
                self.bank.delete_account(acc.acc_no, acc.acc_no)
                self.user = None
                self.show_auth()
                self.stage.toast("Your account has been closed", True)
        Pill(t, "Close my account", close, w=220, h=44, color=CORAL).pack(anchor="w")

    # ----- admin -----
    def admin_login(self):
        pw = simpledialog.askstring("Admin login", "Admin password", show="\u2022", parent=self.root)
        if pw is None:
            return
        ok, message = self.bank.admin_login(pw, get_admin_password())
        if ok:
            self.show_admin()
        else:
            self.stage.toast(message, False)

    def show_admin(self):
        self.clear()
        self.admin, self.last = True, time.time()
        fr = self.card(30, 40, 980, 620, pad=26)
        top = tk.Frame(fr, bg=CREAM)
        top.pack(fill="x")
        label(top, "Admin console", size=24).pack(side="left")
        Pill(top, "Log out", self.show_auth, w=120, h=38, color=CORAL, size=10).pack(side="right")
        self.stats = label(fr, "", size=10, bold=False, fg="#7a5fc0")
        self.stats.pack(fill="x", pady=(2, 6))
        self.search = entry(fr, width=40)
        self.search.pack(anchor="w", ipady=4, pady=(0, 8))
        self.search.bind("<KeyRelease>", lambda e: self.fill_admin())
        bar = tk.Frame(fr, bg=CREAM)
        bar.pack(side="bottom", fill="x", pady=(8, 0))
        self.atree = self.table(fr, ("Account", "Name", "Username", "Type", "Balance", "Status"), (100, 210, 160, 100, 140, 100), 10)
        self.atree.pack(fill="x")
        acts = (("Freeze / unfreeze", self.a_freeze), ("Unlock", self.a_unlock), ("Reset PIN", self.a_pin), ("History", self.a_hist),
                ("Delete", self.a_delete), ("Apply interest", self.a_interest), ("Audit log", self.a_audit),
                ("Backup", self.a_backup), ("Restore", self.a_restore))
        for i, (text, fn) in enumerate(acts):
            Pill(bar, text, fn, w=168, h=38, size=10, color=CORAL if text == "Delete" else PURPLE).grid(
                row=i // 5, column=i % 5, padx=(0, 10), pady=4, sticky="w")
        self.fill_admin()
        self.stage.reveal()

    def fill_admin(self):
        q = self.search.get().strip().lower()
        self.atree.delete(*self.atree.get_children())
        for a in self.bank.accounts.values():
            if q in f"{a.name} {a.username} {a.acc_no}".lower():
                self.atree.insert("", "end", values=(a.acc_no, a.name, a.username, a.acc_type, f"{a.balance:,.2f}", a.status))
        accs = list(self.bank.accounts.values())
        self.stats.config(text=f"{len(accs)} accounts   \u2022   Total money {money(self.bank.total_balance())}   \u2022   "
                               f"{sum(1 for a in accs if a.status != 'active')} frozen   \u2022   {sum(1 for a in accs if a.lock_seconds_left())} locked")

    def picked(self):
        sel = self.atree.selection()
        acc = self.bank.accounts.get(str(self.atree.item(sel[0])["values"][0])) if sel else None
        if acc is None:
            self.stage.toast("Select an account first", False)
        return acc

    def a_done(self, message):
        self.bank.save()
        self.fill_admin()
        self.stage.toast(message, True)

    def a_freeze(self):
        acc = self.picked()
        if acc:
            acc.status = "active" if acc.status == "frozen" else "frozen"
            self.bank.log("admin", f"Account {acc.acc_no} set to {acc.status}")
            self.a_done(f"Account is now {acc.status}")

    def a_unlock(self):
        acc = self.picked()
        if acc:
            acc.unlock()
            self.bank.log("admin", f"Account {acc.acc_no} unlocked")
            self.a_done("Account unlocked")

    def a_pin(self):
        acc = self.picked()
        if acc:
            pin = simpledialog.askstring("Reset PIN", "New PIN for this user (4-8 digits)", show="\u2022", parent=self.root)
            if pin is None:
                return
            if valid_pin(pin):
                acc.set_pin(pin)
                acc.unlock()
                self.bank.log("admin", f"PIN reset for account {acc.acc_no}")
                self.a_done("PIN reset done")
            else:
                self.stage.toast("PIN must be 4 to 8 digits", False)

    def popup(self, title, text):
        win = tk.Toplevel(self.root)
        win.title(title)
        box = tk.Text(win, width=100, height=26, font=("Consolas", 10), bg="white", fg=DEEP)
        box.insert("1.0", text)
        box.config(state="disabled")
        box.pack(padx=10, pady=10)

    def a_hist(self):
        acc = self.picked()
        if acc:
            lines = [f"{h.get('date', '')} {h.get('time', '')}  {h.get('type', ''):14} {h.get('amount', 0):>12,.2f} "
                     f"{h.get('balance', 0):>13,.2f}  {h.get('ref', '')}" for h in reversed(acc.history)]
            self.popup(f"History - {acc.name}", "\n".join(lines) or "No transactions.")

    def a_delete(self):
        acc = self.picked()
        if acc and messagebox.askyesno("Delete account", f"Delete {acc.name} ({acc.acc_no}) for good?"):
            self.bank.delete_account(acc.acc_no, "admin")
            self.a_done("Account deleted")

    def a_interest(self):
        ok, message = self.bank.apply_interest()
        self.bank.save()
        self.fill_admin()
        self.stage.toast(message, ok)

    def a_audit(self):
        self.popup("Audit log", "\n".join(f"{e['time']}  {e['who']:12} {e['event']}" for e in reversed(self.bank.audit[-100:])) or "No events yet.")

    def a_backup(self):
        path = filedialog.asksaveasfilename(defaultextension=".json", initialfile="bank_backup.json", filetypes=[("JSON", "*.json")])
        if path:
            with open(path, "w", encoding="utf-8") as f:
                f.write(self.bank.export_backup())
            self.stage.toast("Backup saved", True)

    def a_restore(self):
        path = filedialog.askopenfilename(filetypes=[("JSON", "*.json")])
        if path and messagebox.askyesno("Restore", "This replaces ALL current data. Continue?"):
            with open(path, encoding="utf-8") as f:
                ok, message = self.bank.restore_backup(f.read())
            self.fill_admin()
            self.stage.toast(message, ok)


def main():
    App().run()


if __name__ == "__main__":
    main()
