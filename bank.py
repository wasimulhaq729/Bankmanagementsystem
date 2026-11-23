"""
NovaVault Bank - Bank Account Management System 

Project scope used: functions, loops, if/else, file handling,
classes and objects.

Features: login with lockout, deposit / withdraw / transfer with PIN
confirmation, transaction reference numbers, saved payees, statement with
filters, charts and PDF / CSV download, savings interest, admin console,
backup / restore, auto logout after 10 minutes.
"""
import csv
import hashlib
import hmac
import html
import io
import json
import os
import random
import re
import time
from datetime import date, datetime

import streamlit as st

# ---------------- Settings ----------------
DATA_FILE = "accounts.json"
MIN_BALANCE = {"Savings": 500.0, "Current": 0.0}  # also the minimum opening deposit
DAILY_LIMIT = 50000.0          # max money going out per day (withdraw + transfer)
MAX_DEPOSIT = 1000000.0        # max single deposit
MAX_ATTEMPTS = 3               # wrong PINs before lock
LOCK_SECONDS = 300             # lock time (5 minutes)
INTEREST_RATE = 4.0            # yearly % for Savings accounts
SESSION_TIMEOUT = 600        # auto logout after 10 minutes without activity
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
    return f"₹ {value:,.2f}"


def valid_pin(pin):
    return pin.isdigit() and 4 <= len(pin) <= 8


def new_ref():
    """Short unique reference number for every transaction."""
    return "TXN" + os.urandom(4).hex().upper()


def get_admin_password():
    """Admin password comes from Streamlit secrets or an environment variable."""
    try:
        return st.secrets["ADMIN_PASSWORD"]
    except Exception:
        return os.environ.get("ADMIN_PASSWORD")


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
#                           SCREEN HELPERS
# =====================================================================
NV_CSS = """<style>
@import url('https://fonts.googleapis.com/css2?family=Poppins:wght@400;600;700;800&display=swap');
@keyframes nvFadeUp { from {opacity:0; transform:translateY(18px);} to {opacity:1; transform:none;} }
@keyframes nvGradient { 0%{background-position:0% 50%} 50%{background-position:100% 50%} 100%{background-position:0% 50%} }
@keyframes nvFloat { 0%,100%{transform:translateY(0) rotate(0deg)} 50%{transform:translateY(-16px) rotate(8deg)} }
@keyframes nvSplash { 0%,65%{opacity:1; visibility:visible} 100%{opacity:0; visibility:hidden} }
@keyframes nvPop { 0%{transform:scale(.6); opacity:0} 60%{transform:scale(1.08); opacity:1} 100%{transform:scale(1)} }
@keyframes nvShine { 0%{left:-70%} 100%{left:140%} }
@keyframes nvGlow { 0%,100%{box-shadow:0 16px 36px rgba(79,70,229,.38), 0 0 0 rgba(168,85,247,0)} 50%{box-shadow:0 20px 48px rgba(124,58,237,.55), 0 0 38px rgba(219,39,119,.35)} }
@keyframes nvHolo { 0%{filter:hue-rotate(0deg)} 100%{filter:hue-rotate(360deg)} }
@keyframes nvOrb { 0%,100%{transform:translate(0,0) scale(1)} 50%{transform:translate(4%,6%) scale(1.15)} }
@keyframes nvIce { 0%,100%{opacity:.55} 50%{opacity:.9} }
@keyframes nvText { to{background-position:200% center} }

.block-container { padding-top: 2rem; max-width: 900px; }
footer { visibility: hidden; }

.nv-splash {
  position: fixed; inset: 0; z-index: 99999; pointer-events: none;
  display: flex; flex-direction: column; align-items: center; justify-content: center;
  background: linear-gradient(135deg, #1e1b4b, #4c1d95, #0e7490);
  color: #fff; font-family: 'Poppins', sans-serif;
  animation: nvSplash 2.6s ease forwards;
}
.nv-splash .nv-logo { font-size: 4.5rem; animation: nvPop .9s ease both; }
.nv-splash .nv-name { font-size: 2.2rem; font-weight: 800; letter-spacing: 3px; animation: nvFadeUp 1s ease .3s both; }
.nv-splash .nv-sub { opacity: .8; animation: nvFadeUp 1s ease .6s both; }

.nv-hero {
  position: relative; overflow: hidden; text-align: center; color: #fff;
  padding: 2.4rem 1rem 2rem; border-radius: 26px; margin-bottom: 1.2rem;
  background: linear-gradient(135deg, #312e81, #6d28d9, #0891b2, #312e81);
  background-size: 300% 300%;
  animation: nvGradient 12s ease infinite, nvFadeUp .8s ease both;
  box-shadow: 0 18px 40px rgba(76, 29, 149, .35);
  font-family: 'Poppins', sans-serif;
}
.nv-hero .nv-badge {
  display: inline-block; padding: 4px 14px; border-radius: 999px; font-size: .78rem;
  background: rgba(255,255,255,.18); border: 1px solid rgba(255,255,255,.35); letter-spacing: 1px;
}
.nv-hero .nv-title { font-size: clamp(2.2rem, 7vw, 3.6rem); font-weight: 800; letter-spacing: 2px; margin: .5rem 0 0; line-height: 1.1; }
.nv-hero .nv-title span { background: linear-gradient(90deg, #fde68a, #fff, #a5f3fc); -webkit-background-clip: text; background-clip: text; color: transparent; }
.nv-hero .nv-tag { opacity: .9; margin: .4rem 0 0; font-size: 1rem; }
.nv-hero .nv-float { position: absolute; font-size: 1.8rem; opacity: .55; animation: nvFloat 6s ease-in-out infinite; }
.nv-hero .f1 { left: 8%; top: 18%; }
.nv-hero .f2 { right: 10%; top: 12%; animation-delay: 1.2s; }
.nv-hero .f3 { left: 18%; bottom: 10%; animation-delay: 2.4s; }
.nv-hero .f4 { right: 16%; bottom: 14%; animation-delay: 3.4s; }

.nv-chips { display: flex; flex-wrap: wrap; gap: 10px; margin: 0 0 1rem; }
.nv-chip2 {
  flex: 1 1 170px; text-align: center; padding: .8rem 1rem; border-radius: 16px; font-size: .9rem;
  border: 1px solid rgba(128,128,128,.25); background: rgba(128,128,128,.07);
  animation: nvFadeUp .8s ease both; transition: transform .2s, box-shadow .2s;
}
.nv-chip2:hover { transform: translateY(-5px); box-shadow: 0 10px 22px rgba(99,102,241,.25); }

.nv-compact {
  font-family: 'Poppins', sans-serif; font-size: 1.15rem; padding: .55rem 1rem; border-radius: 14px;
  margin-bottom: .8rem; color: #fff; animation: nvFadeUp .5s ease both;
  background: linear-gradient(90deg, #312e81, #6d28d9, #0891b2);
}
.nv-compact span { opacity: .8; }


[data-testid="stMetric"] {
  border: 1px solid rgba(128,128,128,.25); background: rgba(128,128,128,.07);
  border-radius: 18px; padding: .9rem 1.1rem; transition: transform .2s, box-shadow .2s;
  animation: nvFadeUp .6s ease both;
}
[data-testid="stMetric"]:hover { transform: translateY(-4px); box-shadow: 0 10px 24px rgba(99,102,241,.22); }

[data-testid="stForm"] {
  border-radius: 20px; border: 1px solid rgba(128,128,128,.25);
  background: rgba(128,128,128,.05); padding: 1.2rem; animation: nvFadeUp .6s ease both;
}

.stTabs [data-baseweb="tab-list"] { gap: 8px; }
.stTabs button[role="tab"] { border-radius: 999px !important; padding: 8px 18px; transition: background .2s; }
.stTabs button[role="tab"]:hover { background: rgba(99,102,241,.10); }
.stTabs button[aria-selected="true"] { background: rgba(99,102,241,.22); border-radius: 999px !important; }

.stButton > button, [data-testid="stFormSubmitButton"] > button, [data-testid="stDownloadButton"] > button {
  background: linear-gradient(90deg, #6366f1, #8b5cf6); border: none; border-radius: 12px;
  padding: .55rem 1.3rem; font-weight: 600; transition: transform .15s, box-shadow .15s;
}
.stButton > button *, [data-testid="stFormSubmitButton"] > button *, [data-testid="stDownloadButton"] > button * { color: #fff !important; }
.stButton > button:hover, [data-testid="stFormSubmitButton"] > button:hover, [data-testid="stDownloadButton"] > button:hover {
  transform: translateY(-2px); box-shadow: 0 8px 20px rgba(99,102,241,.4);
}

.nv-footer { text-align: center; opacity: .6; font-size: .8rem; margin-top: 2.2rem; font-family: 'Poppins', sans-serif; }
/* ---- balance card: native Streamlit containers styled with CSS only ---- */
.st-key-nvstack { position: relative; perspective: 1100px; margin: .8rem 0 2.4rem; }
.st-key-nvstack::before, .st-key-nvstack::after {
  content: ""; position: absolute; left: 5%; right: 5%; top: 0; bottom: 0; border-radius: 24px;
  transition: transform .45s cubic-bezier(.2,.8,.2,1);
}
.st-key-nvstack::before { background: linear-gradient(135deg, #0891b2, #6366f1); opacity: .45; transform: translateY(14px) scale(.94); }
.st-key-nvstack::after  { background: linear-gradient(135deg, #db2777, #7c3aed); opacity: .28; transform: translateY(26px) scale(.88); z-index: -1; }
.st-key-nvstack:hover::before { transform: translateY(20px) scale(.95); }
.st-key-nvstack:hover::after  { transform: translateY(38px) scale(.9); }

[class*="st-key-nvcard_"] {
  position: relative; z-index: 1; overflow: hidden; border-radius: 24px; padding: 1.4rem 1.6rem; gap: .2rem;
  background:
    url("data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' width='44' height='32' viewBox='0 0 44 32'><defs><linearGradient id='g' x1='0' y1='0' x2='1' y2='1'><stop offset='0' stop-color='%23fde68a'/><stop offset='.55' stop-color='%23f59e0b'/><stop offset='1' stop-color='%23fde68a'/></linearGradient></defs><rect width='44' height='32' rx='7' fill='url(%23g)'/><path d='M0 11h14M0 21h14M30 11h14M30 21h14M14 0v32M30 0v32' stroke='%23b45309' stroke-opacity='.4' fill='none'/><rect x='14' y='9' width='16' height='14' rx='3' fill='none' stroke='%23b45309' stroke-opacity='.4'/></svg>") right 1.6rem top 1.4rem / 44px 32px no-repeat,
    linear-gradient(135deg, #4f46e5, #7c3aed 55%, #db2777);
  transform-style: preserve-3d; transition: transform .45s cubic-bezier(.2,.8,.2,1);
  animation: nvFadeUp .6s ease both, nvGlow 4s ease-in-out infinite;
}
.st-key-nvstack:hover [class*="st-key-nvcard_"] { transform: rotateX(5deg) rotateY(-7deg) translateY(-4px); }
[class*="st-key-nvcard_"] * { color: #fff !important; font-family: 'Poppins', sans-serif; }
[class*="st-key-nvcard_"] > * { position: relative; z-index: 2; }
[class*="st-key-nvcard_"] h2 { font-size: clamp(1.8rem, 6vw, 2.6rem); font-weight: 800; padding: 0; margin: 0 0 .6rem; transition: filter .35s ease; }
[class*="st-key-nvcard_"] [data-testid="stCaptionContainer"] { opacity: .8; }
[class*="st-key-nvcard_"] a { display: none; }
[class*="st-key-nvcard_"]::before {          /* holographic sheen */
  content: ""; position: absolute; inset: 0; pointer-events: none; mix-blend-mode: overlay; opacity: .35;
  background: conic-gradient(from 210deg at 80% 20%, #fde68a, #a5f3fc, #f0abfc, #fde68a);
  animation: nvHolo 9s linear infinite;
}
[class*="st-key-nvcard_"]::after {           /* moving shine */
  content: ""; position: absolute; top: 0; left: -70%; width: 40%; height: 100%; pointer-events: none;
  background: linear-gradient(120deg, transparent, rgba(255,255,255,.28), transparent);
  transform: skewX(-20deg); animation: nvShine 4.5s ease-in-out infinite;
}
[class*="st-key-nvcard_"][class*="_hide"] h2 { filter: blur(11px); user-select: none; }
[class*="st-key-nvcard_frozen_"] {
  background: linear-gradient(135deg, #475569, #64748b); animation: nvFadeUp .6s ease both;
}
[class*="st-key-nvcard_frozen_"]::before {
  mix-blend-mode: normal; opacity: .55; animation: nvIce 3s ease-in-out infinite;
  background: linear-gradient(160deg, rgba(255,255,255,.35), rgba(186,230,253,.12) 45%, rgba(255,255,255,.3));
}
[class*="st-key-nvcard_frozen_"]::after { animation-duration: 9s; }

/* ---- ambient glow, tabs, footer ---- */
.stApp::before {
  content: ""; position: fixed; inset: -10%; z-index: 0; pointer-events: none; opacity: .16;
  background:
    radial-gradient(circle at 15% 20%, #6d28d9 0, transparent 38%),
    radial-gradient(circle at 85% 75%, #0891b2 0, transparent 40%),
    radial-gradient(circle at 70% 10%, #db2777 0, transparent 30%);
  animation: nvOrb 16s ease-in-out infinite;
}
.stTabs [data-baseweb="tab-highlight"] { display: none; }
[data-testid="stColumn"]:nth-child(2) [data-testid="stMetric"] { animation-delay: .12s; }
.nv-footer {
  background: linear-gradient(90deg, #888, #8b5cf6, #0891b2, #888); background-size: 200% auto;
  -webkit-background-clip: text; background-clip: text; color: transparent; opacity: .85;
  animation: nvText 6s linear infinite;
}
@media (prefers-reduced-motion: reduce) {
  *, *::before, *::after { animation: none !important; transition: none !important; }
}
</style>"""

SPLASH_HTML = (
    '<div class="nv-splash">'
    '<div class="nv-logo">💠</div>'
    '<div class="nv-name">NOVAVAULT</div>'
    '<div class="nv-sub">Opening your vault...</div>'
    '</div>'
)

HERO_HTML = (
    '<div class="nv-hero">'
    '<span class="nv-float f1">🪙</span><span class="nv-float f2">💎</span>'
    '<span class="nv-float f3">💰</span><span class="nv-float f4">🔐</span>'
    '<div class="nv-badge">SECURE &bull; INSTANT &bull; SMART</div>'
    '<div class="nv-title">Nova<span>Vault</span></div>'
    '<div class="nv-tag">Your money. Your vault. Your rules.</div>'
    '</div>'
)


def inject_css():
    st.markdown(NV_CSS, unsafe_allow_html=True)


def render_header(logged_in):
    """Big animated hero on the login screen, slim bar after login."""
    if logged_in:
        st.markdown(
            '<div class="nv-compact">💠 <b>NovaVault</b> <span>Bank</span></div>',
            unsafe_allow_html=True,
        )
        return
    if not st.session_state.get("splash_shown"):
        st.session_state["splash_shown"] = True
        st.markdown(SPLASH_HTML, unsafe_allow_html=True)
    st.markdown(HERO_HTML, unsafe_allow_html=True)
    st.markdown(
        '<div class="nv-chips">'
        '<div class="nv-chip2">🔒 Hashed PIN<br><small>Your PIN is never stored</small></div>'
        '<div class="nv-chip2">⚡ Instant transfers<br><small>Send money by username</small></div>'
        f'<div class="nv-chip2">📈 {INTEREST_RATE}% interest<br><small>On Savings accounts</small></div>'
        '</div>',
        unsafe_allow_html=True,
    )


def md_safe(text):
    """Escape markdown characters, because names come from users."""
    return re.sub(r"([\\`*_{}\[\]()#+\-.!|<>~$])", r"\\\1", str(text))


def box(key):
    """A container with a CSS class (st-key-<key>); older Streamlit has no key."""
    try:
        return st.container(key=key)
    except TypeError:
        return st.container()


def balance_card(acc, hide=False):
    """Credit-card style balance box built from Streamlit containers, styled only by CSS."""
    number = f"{acc.acc_no[:4]} {acc.acc_no[4:]}"
    frozen = acc.status != "active"
    state = "FROZEN" if frozen else "ACTIVE"
    key = f"nvcard_{'frozen' if frozen else 'active'}_{'hide' if hide else 'show'}"
    with box("nvstack"):
        with box(key):
            st.markdown(f"**{md_safe(acc.acc_type.upper())} ACCOUNT** · ● {state}")
            st.caption("")
            st.caption("Available balance")
            st.markdown(f"## {money(acc.balance)}")
            c1, c2 = st.columns(2)
            c1.caption("ACCOUNT NO.")
            c1.markdown(f"**{number}**")
            c2.caption("HOLDER")
            c2.markdown(f"**{md_safe(acc.name.upper())}**")


def render_footer():
    st.markdown(
        '<div class="nv-footer">NovaVault Bank &bull; Since 2026</div>',
        unsafe_allow_html=True,
    )


def flash(kind, message):
    """Show a message on the next screen (needed because we call rerun)."""
    st.session_state["flash"] = (kind, message)


def show_flash():
    item = st.session_state.pop("flash", None)
    if item:
        if item[0] == "success" and hasattr(st, "toast"):
            st.toast(item[1], icon="✅")
        else:
            getattr(st, item[0])(item[1])


def logout():
    st.session_state["user"] = None
    st.session_state["role"] = None
    st.rerun()


def finish(bank, result):
    """Save and refresh when an action worked, otherwise show the error."""
    ok, message = result
    if ok:
        bank.save()
        flash("success", message)
        st.rerun()
    else:
        st.error(message)


def history_rows(history):
    rows = []
    for h in reversed(history):
        rows.append({
            "Date": h.get("date", "-"),
            "Time": h.get("time", "-"),
            "Type": h.get("type", ""),
            "Amount": h.get("amount", 0),
            "Balance": h.get("balance", 0),
            "Note": h.get("note", ""),
            "Ref": h.get("ref", "-"),
        })
    return rows


def rows_to_csv(rows):
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(["Date", "Time", "Type", "Amount", "Balance", "Note", "Ref"])
    for r in rows:
        writer.writerow([r["Date"], r["Time"], r["Type"], r["Amount"], r["Balance"], r["Note"], r["Ref"]])
    return buffer.getvalue()


def statement_pdf(acc, rows, start, end):
    """Build a simple statement PDF by hand (no extra library needed)."""
    def clean(text, width=None):
        text = str(text).replace("₹", "Rs.").encode("latin-1", "replace").decode("latin-1")
        text = text.replace("\\", "/").replace("(", "[").replace(")", "]")
        return text[:width] if width else text

    def num(v):
        return f"{v:,.2f}"

    head = [
        ("B", 16, "NovaVault Bank"),
        ("N", 10, "Account statement"),
        ("N", 10, ""),
        ("N", 10, f"Holder   : {clean(acc.name)}"),
        ("N", 10, f"Account  : {acc.acc_no}  ({clean(acc.acc_type)})"),
        ("N", 10, f"Period   : {start}  to  {end}"),
        ("N", 10, f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M')}"),
        ("N", 10, ""),
        ("B", 9, f"{'Date':<10} {'Time':<8} {'Type':<13} {'Amount':>12} {'Balance':>12} {'Ref':<11} Note"),
        ("N", 9, "-" * 94),
    ]
    body = []
    for r in reversed(rows):                       # oldest first on paper
        body.append(("N", 9, (
            f"{clean(r['Date'], 10):<10} {clean(r['Time'], 8):<8} {clean(r['Type'], 13):<13} "
            f"{num(r['Amount']):>12} {num(r['Balance']):>12} {clean(r['Ref'], 11):<11} {clean(r['Note'], 24)}"
        )))
    if not body:
        body.append(("N", 9, "No transactions in this period."))
    body.append(("N", 9, "-" * 94))
    body.append(("N", 8, "This statement was generated by NovaVault Bank (demo project)."))

    lines = head + body
    per_page = 58
    pages = [lines[i:i + per_page] for i in range(0, len(lines), per_page)]

    objects = []                                    # index 0 -> object 1
    objects.append("<< /Type /Catalog /Pages 2 0 R >>")
    kids = " ".join(f"{5 + 2 * i} 0 R" for i in range(len(pages)))
    objects.append(f"<< /Type /Pages /Kids [{kids}] /Count {len(pages)} >>")
    objects.append("<< /Type /Font /Subtype /Type1 /BaseFont /Courier /Encoding /WinAnsiEncoding >>")
    objects.append("<< /Type /Font /Subtype /Type1 /BaseFont /Courier-Bold /Encoding /WinAnsiEncoding >>")
    for i, page in enumerate(pages):
        y = 800
        parts = []
        for style, size, text in page:
            font = "F2" if style == "B" else "F1"
            parts.append(f"BT /{font} {size} Tf 40 {y} Td ({text}) Tj ET")
            y -= size + 3.5 if size > 9 else 12
        stream = "\n".join(parts)
        objects.append(
            "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] "
            "/Resources << /Font << /F1 3 0 R /F2 4 0 R >> >> "
            f"/Contents {6 + 2 * i} 0 R >>"
        )
        objects.append(f"<< /Length {len(stream.encode('latin-1', 'replace'))} >>\nstream\n{stream}\nendstream")

    out = bytearray(b"%PDF-1.4\n")
    offsets = []
    for n, body_text in enumerate(objects, start=1):
        offsets.append(len(out))
        out += f"{n} 0 obj\n".encode() + body_text.encode("latin-1", "replace") + b"\nendobj\n"
    xref = len(out)
    out += f"xref\n0 {len(objects) + 1}\n0000000000 65535 f \n".encode()
    for off in offsets:
        out += f"{off:010d} 00000 n \n".encode()
    out += f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF".encode()
    return bytes(out)


# =====================================================================
#                               PAGES
# =====================================================================
def login_page(bank):
    tab_login, tab_create, tab_forgot = st.tabs(["Login", "Create account", "Forgot PIN"])

    with tab_login:
        with st.form("login_form"):
            identifier = st.text_input("Username or account number")
            pin = st.text_input("PIN / Password", type="password")
            go = st.form_submit_button("Login")
        if go:
            identifier = identifier.strip()
            if identifier.lower() == "admin":
                ok, message = bank.admin_login(pin, get_admin_password())
                if ok:
                    st.session_state["user"] = "admin"
                    st.session_state["role"] = "admin"
                    st.rerun()
                st.error(message)
            else:
                acc, message = bank.authenticate(identifier, pin)
                if acc:
                    st.session_state["user"] = acc.acc_no
                    st.session_state["role"] = "user"
                    st.rerun()
                st.error(message)
        if not get_admin_password():
            st.caption("Admin login is off (ADMIN_PASSWORD secret is not set).")

    with tab_create:
        with st.form("create_form"):
            name = st.text_input("Full name*")
            username = st.text_input("Username* (3-20 letters, digits or _)")
            acc_type = st.selectbox("Account type", ["Savings", "Current"])
            new_pin = st.text_input("PIN (4-8 digits)*", type="password")
            confirm_pin = st.text_input("Confirm PIN*", type="password")
            question = st.selectbox("Security question (for forgot PIN)", SECURITY_QUESTIONS)
            answer = st.text_input("Security answer*")
            opening = st.number_input("Opening deposit", min_value=0.0, step=100.0)
            go = st.form_submit_button("Create account")
        st.caption(
            f"Savings: minimum opening deposit and balance {money(MIN_BALANCE['Savings'])}, "
            f"earns {INTEREST_RATE}% yearly interest. Current: no minimum."
        )
        if go:
            ok, message, acc = bank.create_account(
                name, username, acc_type, new_pin, confirm_pin, opening, question, answer
            )
            if ok:
                st.success(f"Account created! Account number: {acc.acc_no}")
                st.info(f"You can log in with your username ({acc.username}) or the account number.")
            else:
                st.error(message)

    with tab_forgot:
        st.write("Forgot your PIN? Answer your security question to set a new one.")
        if st.session_state.pop("clear_forgot", False):
            st.session_state["forgot_id"] = ""
        forgot_id = st.text_input("Username or account number", key="forgot_id").strip()
        target = bank.find(forgot_id) if forgot_id else None
        if forgot_id:
            if target and target.has_security():
                st.info(f"Security question: {target.sec_question}")
            else:
                st.warning("Account not found, or no security question was set. "
                           "Please contact the admin to reset your PIN.")
        with st.form("forgot_form"):
            answer = st.text_input("Your answer")
            new_pin = st.text_input("New PIN (4-8 digits)", type="password")
            confirm = st.text_input("Confirm new PIN", type="password")
            go = st.form_submit_button("Reset PIN")
        if go:
            ok, message = bank.reset_pin_with_answer(forgot_id, answer, new_pin, confirm)
            if ok:
                st.session_state["clear_forgot"] = True
                flash("success", message)
                st.rerun()
            st.error(message)


def pick_payee():
    """Callback: copy the chosen saved payee into the receiver box."""
    st.session_state["transfer_to"] = st.session_state.get("payee_pick", "")


def month_totals(rows):
    """Money in / money out per month for the statement chart."""
    months = sorted({r["Date"][:7] for r in rows if r["Date"] != "-"})
    money_in = {m: 0.0 for m in months}
    money_out = {m: 0.0 for m in months}
    for r in rows:
        month = r["Date"][:7]
        if month not in money_in:
            continue
        if r["Type"] in MONEY_IN:
            money_in[month] += r["Amount"]
        elif r["Type"] in MONEY_OUT:
            money_out[month] += r["Amount"]
    return {"Money in": money_in, "Money out": money_out}


def user_page(bank, acc):
    c1, c2 = st.columns([3, 1])
    c1.subheader(f"Welcome back, {acc.name} 👋")
    if c2.button("Logout"):
        logout()

    if acc.status != "active":
        st.error("Your account is frozen. Please contact the admin.")
    hide = False
    if hasattr(st, "toggle"):
        hide = st.toggle("🙈 Hide balance", key="hide_balance")
    balance_card(acc, hide)
    st.caption(f"Username: {acc.username or '-'}")
    if acc.acc_type == "Savings":
        estimate = round(acc.balance * INTEREST_RATE / 100 / 12, 2)
        st.caption(f"📈 Earns {INTEREST_RATE}% a year. Estimated interest next month: {money(estimate)}")
    if acc.lock_seconds_left():
        st.warning("Payments are paused for a few minutes after too many wrong PINs.")

    m1, m2 = st.columns(2)
    m1.metric("Daily limit left", money(max(DAILY_LIMIT - acc.today_out(), 0)))
    m2.metric("Spent today", money(acc.today_out()))

    tab_dep, tab_wd, tab_tr, tab_st, tab_pf = st.tabs(
        ["Deposit", "Withdraw", "Transfer", "Statement", "Profile"]
    )

    with tab_dep:
        with st.form("deposit_form", clear_on_submit=True):
            amount = st.number_input("Amount", min_value=0.0, max_value=MAX_DEPOSIT, step=100.0)
            go = st.form_submit_button("Deposit")
        if go:
            finish(bank, acc.deposit(amount))

    with tab_wd:
        with st.form("withdraw_form", clear_on_submit=True):
            amount = st.number_input("Amount", min_value=0.0, step=100.0)
            pin = st.text_input("Enter your PIN to confirm", type="password")
            go = st.form_submit_button("Withdraw")
        if go:
            ok, error = bank.verify_pin(acc, pin)
            if ok:
                finish(bank, acc.withdraw(amount))
            else:
                st.error(error)

    with tab_tr:
        payees = [no for no in acc.payees if no in bank.accounts]
        if st.session_state.pop("clear_transfer", False):
            st.session_state["transfer_to"] = ""
            st.session_state["payee_pick"] = ""
        if st.session_state.get("payee_pick", "") not in [""] + payees:
            st.session_state["payee_pick"] = ""
        if payees:
            st.selectbox(
                "Saved payees", [""] + payees, key="payee_pick", on_change=pick_payee,
                format_func=lambda no: "Choose a saved payee" if not no
                else f"{bank.accounts[no].name} ({no})",
            )
        to_id = st.text_input("Receiver username or account number", key="transfer_to").strip()
        receiver = bank.find(to_id) if to_id else None
        if to_id:
            if receiver is None:
                st.warning("Account not found")
            elif receiver.acc_no == acc.acc_no:
                st.warning("You cannot transfer to your own account")
            else:
                st.info(f"Receiver: {receiver.name}")
        with st.form("transfer_form", clear_on_submit=True):
            amount = st.number_input("Amount", min_value=0.0, step=100.0)
            note = st.text_input("Note (optional)", max_chars=60)
            pin = st.text_input("Enter your PIN to confirm", type="password")
            save_payee = st.checkbox("Save this receiver for next time")
            go = st.form_submit_button("Transfer")
        if go:
            if receiver is None:
                st.error("Enter a valid receiver first")
            else:
                ok, error = bank.verify_pin(acc, pin)
                if not ok:
                    st.error(error)
                else:
                    result = acc.send(receiver, amount, note.strip())
                    if result[0]:
                        st.session_state["clear_transfer"] = True
                        if save_payee and receiver.acc_no not in acc.payees:
                            acc.payees.append(receiver.acc_no)
                    finish(bank, result)

    with tab_st:
        today = date.today()
        first = min((h.get("date", today.isoformat()) for h in acc.history), default=today.isoformat())
        try:
            first_day = date.fromisoformat(first)
        except ValueError:
            first_day = today
        f1, f2, f3 = st.columns(3)
        start = f1.date_input("From", value=first_day, max_value=today)
        end = f2.date_input("To", value=today, max_value=today)
        kinds = [""] + sorted({h.get("type", "") for h in acc.history})
        chosen = f3.selectbox("Type", kinds, format_func=lambda k: "All" if not k else k)
        search = st.text_input("Search note or reference").strip().lower()

        if start > end:
            st.error("The 'From' date must be before the 'To' date")
            rows = []
        else:
            rows = [r for r in history_rows(acc.history)
                    if start.isoformat() <= r["Date"] <= end.isoformat()]
        if chosen:
            rows = [r for r in rows if r["Type"] == chosen]
        if search:
            rows = [r for r in rows if search in f"{r['Note']} {r['Ref']}".lower()]

        total_in, total_out = 0.0, 0.0
        for r in rows:
            if r["Type"] in MONEY_IN:
                total_in += r["Amount"]
            elif r["Type"] in MONEY_OUT:
                total_out += r["Amount"]
        s1, s2, s3 = st.columns(3)
        s1.metric("Money in", money(total_in))
        s2.metric("Money out", money(total_out))
        s3.metric("Transactions", len(rows))
        if rows:
            st.dataframe(rows)
            if len(rows) > 1:
                st.markdown("##### Money in and out by month")
                st.bar_chart(month_totals(rows))
                st.markdown("##### Balance trend")
                st.line_chart({"Balance": [r["Balance"] for r in reversed(rows)]})
            d1, d2 = st.columns(2)
            d1.download_button("Download statement (PDF)",
                               statement_pdf(acc, rows, start.isoformat(), end.isoformat()),
                               file_name=f"statement_{acc.acc_no}.pdf", mime="application/pdf")
            d2.download_button("Download statement (CSV)", rows_to_csv(rows),
                               file_name=f"statement_{acc.acc_no}.csv", mime="text/csv")
        else:
            st.info("No transactions for these filters.")

    with tab_pf:
        st.write(f"**Name:** {acc.name}")
        st.write(f"**Username:** {acc.username or '-'}")
        st.write(f"**Account number:** {acc.acc_no}")
        st.write(f"**Account type:** {acc.acc_type}")
        st.write(f"**Opened on:** {acc.created or '-'}")
        st.write(f"**Status:** {acc.status.title()}")

        saved = [no for no in acc.payees if no in bank.accounts]
        if saved:
            st.markdown("##### Saved payees")
            with st.form("remove_payee_form", clear_on_submit=True):
                gone = st.selectbox("Payee", saved, format_func=lambda no: f"{bank.accounts[no].name} ({no})")
                go = st.form_submit_button("Remove payee")
            if go:
                acc.payees = [no for no in acc.payees if no != gone]
                finish(bank, (True, "Payee removed"))

        st.markdown("##### Change PIN")
        with st.form("change_pin_form", clear_on_submit=True):
            old_pin = st.text_input("Current PIN", type="password")
            new_pin = st.text_input("New PIN (4-8 digits)", type="password")
            confirm = st.text_input("Confirm new PIN", type="password")
            go = st.form_submit_button("Change PIN")
        if go:
            if not acc.check_pin(old_pin):
                st.error("Current PIN is incorrect")
            elif not valid_pin(new_pin):
                st.error("PIN must be 4 to 8 digits")
            elif new_pin != confirm:
                st.error("New PINs do not match")
            else:
                acc.set_pin(new_pin)
                bank.log(acc.acc_no, "PIN changed")
                finish(bank, (True, "PIN changed successfully"))

        st.markdown("##### Security question (for forgot PIN)")
        if acc.has_security():
            st.caption(f"Current question: {acc.sec_question}")
        else:
            st.warning("No security question set yet. Set one so you can reset a forgotten PIN.")
        with st.form("security_form", clear_on_submit=True):
            question = st.selectbox("Question", SECURITY_QUESTIONS)
            answer = st.text_input("Answer")
            pin_check = st.text_input("Enter your PIN to confirm", type="password")
            go = st.form_submit_button("Save security question")
        if go:
            if not acc.check_pin(pin_check):
                st.error("Incorrect PIN")
            elif len(answer.strip()) < 3:
                st.error("Answer must be at least 3 characters")
            else:
                acc.set_security(question, answer)
                bank.log(acc.acc_no, "Security question updated")
                finish(bank, (True, "Security question saved"))

        st.markdown("##### Close account")
        st.warning(
            f"Closing the account pays out your remaining balance ({money(acc.balance)}) "
            "and cannot be undone."
        )
        with st.form("close_form"):
            pin_check = st.text_input("Enter your PIN to confirm", type="password")
            sure = st.checkbox("Yes, close my account")
            go = st.form_submit_button("Close my account")
        if go:
            if not sure:
                st.error("Please tick the checkbox first")
            elif not acc.check_pin(pin_check):
                st.error("Incorrect PIN")
            else:
                bank.delete_account(acc.acc_no, acc.acc_no)
                st.session_state["user"] = None
                st.session_state["role"] = None
                flash("success", "Your account has been closed")
                st.rerun()


def admin_page(bank):
    c1, c2 = st.columns([3, 1])
    c1.subheader("🛡️ Admin Console")
    if c2.button("Logout"):
        logout()

    tab_dash, tab_acc, tab_int, tab_audit, tab_bk = st.tabs(
        ["Dashboard", "Accounts", "Interest", "Audit log", "Backup"]
    )
    accounts = list(bank.accounts.values())

    with tab_dash:
        frozen = 0
        locked = 0
        for a in accounts:
            if a.status != "active":
                frozen += 1
            if a.lock_seconds_left():
                locked += 1
        d1, d2 = st.columns(2)
        d1.metric("Accounts", len(accounts))
        d2.metric("Total money", money(bank.total_balance()))
        d3, d4 = st.columns(2)
        d3.metric("Frozen", frozen)
        d4.metric("Locked", locked)

        if accounts:
            st.markdown("##### Balances")
            st.bar_chart({"Balance": {f"{a.name} ({a.acc_no})": a.balance for a in accounts}})
            recent = []
            for a in accounts:
                for h in a.history:
                    recent.append({"Account": a.acc_no, "Name": a.name,
                                   "Date": h.get("date", "-"), "Time": h.get("time", "-"),
                                   "Type": h.get("type", ""), "Amount": h.get("amount", 0)})
            recent.sort(key=lambda r: (r["Date"], r["Time"]), reverse=True)
            st.markdown("##### Latest transactions")
            st.dataframe(recent[:10])

    with tab_acc:
        if not accounts:
            st.info("There are no accounts yet.")
        else:
            query = st.text_input("Search by name, username or account number").strip().lower()
            matches = []
            for a in accounts:
                text = f"{a.name} {a.username} {a.acc_no}".lower()
                if query in text:
                    matches.append(a)
            st.dataframe([{
                "Account": a.acc_no, "Name": a.name, "Username": a.username,
                "Type": a.acc_type, "Balance": a.balance, "Status": a.status,
            } for a in matches])

            if matches:
                st.divider()
                target = st.selectbox(
                    "Select account", [a.acc_no for a in matches],
                    format_func=lambda no: f"{no} - {bank.accounts[no].name}",
                )
                acc = bank.accounts[target]
                st.write(f"**{acc.name}**  |  {acc.acc_type}  |  {money(acc.balance)}  |  {acc.status}")

                with st.expander("Transaction history"):
                    if acc.history:
                        st.dataframe(history_rows(acc.history))
                    else:
                        st.write("No transactions.")

                b1, b2 = st.columns(2)
                label = "Unfreeze account" if acc.status == "frozen" else "Freeze account"
                if b1.button(label):
                    acc.status = "active" if acc.status == "frozen" else "frozen"
                    bank.log("admin", f"Account {acc.acc_no} set to {acc.status}")
                    finish(bank, (True, f"Account is now {acc.status}"))
                if b2.button("Unlock account"):
                    acc.unlock()
                    bank.log("admin", f"Account {acc.acc_no} unlocked")
                    finish(bank, (True, "Account unlocked"))

                with st.form("reset_pin_form", clear_on_submit=True):
                    temp_pin = st.text_input("New PIN for this user (4-8 digits)", type="password")
                    go = st.form_submit_button("Reset PIN")
                if go:
                    if valid_pin(temp_pin):
                        acc.set_pin(temp_pin)
                        acc.unlock()
                        bank.log("admin", f"PIN reset for account {acc.acc_no}")
                        finish(bank, (True, "PIN reset done"))
                    else:
                        st.error("PIN must be 4 to 8 digits")

                sure = st.checkbox("Yes, I want to delete this account", key="admin_delete_ok")
                if st.button("Delete account", type="primary"):
                    if sure:
                        bank.delete_account(acc.acc_no, "admin")
                        finish(bank, (True, "Account deleted"))
                    else:
                        st.warning("Please tick the checkbox first")

    with tab_int:
        st.write(f"Savings accounts earn {INTEREST_RATE}% yearly interest, added monthly.")
        st.caption(f"Last applied for month: {bank.meta.get('last_interest_month') or 'never'}")
        if st.button("Apply this month's interest"):
            finish(bank, bank.apply_interest())

    with tab_audit:
        if bank.audit:
            st.dataframe(list(reversed(bank.audit[-100:])))
        else:
            st.write("No events yet.")

    with tab_bk:
        st.write("Streamlit Cloud can reset files when the app restarts, so download a backup regularly.")
        st.download_button("Download backup", bank.export_backup(),
                           file_name="bank_backup.json", mime="application/json")
        uploaded = st.file_uploader("Restore from backup file", type=["json"])
        sure = st.checkbox("Yes, replace all current data with this backup", key="restore_ok")
        if st.button("Restore backup"):
            if uploaded is None:
                st.error("Choose a backup file first")
            elif not sure:
                st.warning("Please tick the checkbox first")
            else:
                finish(bank, bank.restore_backup(uploaded.getvalue().decode("utf-8", "ignore")))


# =====================================================================
#                                MAIN
# =====================================================================
def main():
    st.set_page_config(page_title="NovaVault Bank", page_icon="💠")
    if "user" not in st.session_state:
        st.session_state["user"] = None
        st.session_state["role"] = None

    if st.session_state["user"] is None:
        st.session_state.pop("last_active", None)
    else:                                          # auto logout after a period of inactivity
        now = time.time()
        if now - st.session_state.get("last_active", now) > SESSION_TIMEOUT:
            flash("info", "You were logged out after 10 minutes of inactivity.")
            logout()
        st.session_state["last_active"] = now

    bank = Bank()
    inject_css()
    render_header(st.session_state["user"] is not None)
    show_flash()

    if st.session_state["user"] is None:
        login_page(bank)
    elif st.session_state["role"] == "admin":
        admin_page(bank)
    else:
        acc = bank.accounts.get(st.session_state["user"])
        if acc is None:     # deleted by admin or data was reset
            st.session_state["user"] = None
            st.session_state["role"] = None
            flash("error", "This account no longer exists.")
            st.rerun()
        else:
            user_page(bank, acc)

    render_footer()


if __name__ == "__main__":
    main()
