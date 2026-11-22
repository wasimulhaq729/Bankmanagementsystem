"""
Bank Account Management System

Project scope used: functions, loops, if/else, file handling,
classes and objects.
"""
import csv
import hashlib
import hmac
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
                 sec_question="", sec_salt="", sec_hash=""):
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

    def _log(self, kind, amount, note=""):
        now = datetime.now()
        self.history.append({
            "date": now.strftime("%Y-%m-%d"),
            "time": now.strftime("%H:%M:%S"),
            "type": kind,
            "amount": amount,
            "balance": self.balance,
            "note": note,
        })

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
        self._log("Deposit", amount)
        return True, f"Deposited {money(amount)}"

    def withdraw(self, amount):
        amount = round(float(amount), 2)
        error = self._debit_error(amount)
        if error:
            return False, error
        self.balance = round(self.balance - amount, 2)
        self._log("Withdraw", amount)
        return True, f"Withdrew {money(amount)}"

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
        self._log("Transfer Out", amount, f"To {other.name} ({other.acc_no}) {note}".strip())
        other._log("Transfer In", amount, f"From {self.name} ({self.acc_no}) {note}".strip())
        return True, f"Sent {money(amount)} to {other.name}"

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
def flash(kind, message):
    """Show a message on the next screen (needed because we call rerun)."""
    st.session_state["flash"] = (kind, message)


def show_flash():
    item = st.session_state.pop("flash", None)
    if item:
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
        })
    return rows


def rows_to_csv(rows):
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(["Date", "Time", "Type", "Amount", "Balance", "Note"])
    for r in rows:
        writer.writerow([r["Date"], r["Time"], r["Type"], r["Amount"], r["Balance"], r["Note"]])
    return buffer.getvalue()


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


def user_page(bank, acc):
    c1, c2 = st.columns([3, 1])
    c1.subheader(f"Welcome, {acc.name}")
    if c2.button("Logout"):
        logout()

    if acc.status != "active":
        st.error("Your account is frozen. Please contact the admin.")
    st.caption(f"Account number: {acc.acc_no}  |  Username: {acc.username or '-'}  |  {acc.acc_type}")

    m1, m2 = st.columns(2)
    m1.metric("Balance", money(acc.balance))
    m2.metric("Daily limit left", money(max(DAILY_LIMIT - acc.today_out(), 0)))

    tab_dep, tab_wd, tab_tr, tab_st, tab_pf = st.tabs(
        ["Deposit", "Withdraw", "Transfer", "Statement", "Profile"]
    )

    with tab_dep:
        with st.form("deposit_form", clear_on_submit=True):
            amount = st.number_input("Amount", min_value=0.0, step=100.0)
            go = st.form_submit_button("Deposit")
        if go:
            finish(bank, acc.deposit(amount))

    with tab_wd:
        with st.form("withdraw_form", clear_on_submit=True):
            amount = st.number_input("Amount", min_value=0.0, step=100.0)
            go = st.form_submit_button("Withdraw")
        if go:
            finish(bank, acc.withdraw(amount))

    with tab_tr:
        if st.session_state.pop("clear_transfer", False):
            st.session_state["transfer_to"] = ""
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
            go = st.form_submit_button("Transfer")
        if go:
            if receiver is None:
                st.error("Enter a valid receiver first")
            else:
                result = acc.send(receiver, amount, note.strip())
                if result[0]:
                    st.session_state["clear_transfer"] = True
                finish(bank, result)

    with tab_st:
        kinds = ["All"] + sorted({h.get("type", "") for h in acc.history})
        chosen = st.selectbox("Show", kinds)
        rows = history_rows(acc.history)
        if chosen != "All":
            rows = [r for r in rows if r["Type"] == chosen]
        total_in, total_out = 0.0, 0.0
        for r in rows:
            if r["Type"] in MONEY_IN:
                total_in += r["Amount"]
            elif r["Type"] in MONEY_OUT:
                total_out += r["Amount"]
        s1, s2 = st.columns(2)
        s1.metric("Money in", money(total_in))
        s2.metric("Money out", money(total_out))
        if rows:
            st.dataframe(rows)
            st.download_button("Download statement (CSV)", rows_to_csv(rows),
                               file_name=f"statement_{acc.acc_no}.csv", mime="text/csv")
        else:
            st.write("No transactions.")

    with tab_pf:
        st.write(f"**Name:** {acc.name}")
        st.write(f"**Account type:** {acc.acc_type}")
        st.write(f"**Opened on:** {acc.created or '-'}")

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
    c1.subheader("Admin panel")
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
    st.set_page_config(page_title="Bank System", page_icon="🏦")
    if "user" not in st.session_state:
        st.session_state["user"] = None
        st.session_state["role"] = None

    bank = Bank()
    st.title("🏦 Bank System")
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


if __name__ == "__main__":
    main()
