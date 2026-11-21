# Bank Account Management System - Streamlit version
# Uses: functions, loops, if/else, file handling, classes and objects
# Run with:  streamlit run bank_app.py

import hashlib
import json
import os
import random
from datetime import datetime

import streamlit as st

DATA_FILE = "accounts.json"

st.set_page_config(page_title="Bank System", page_icon="🏦")


# ---------------- Helpers ----------------
def load_accounts():
    if os.path.exists(DATA_FILE):
        try:
            with open(DATA_FILE, "r") as f:
                return json.load(f)
        except (json.JSONDecodeError, OSError):
            return {}
    return {}


def save_accounts(accounts):
    with open(DATA_FILE, "w") as f:
        json.dump(accounts, f, indent=2)


def hash_pin(pin, salt):
    return hashlib.sha256((salt + pin).encode()).hexdigest()


def get_admin_password():
    try:
        return st.secrets["ADMIN_PASSWORD"]
    except Exception:
        return os.environ.get("ADMIN_PASSWORD")


def add_txn(acc, kind, amount):
    acc["history"].append(
        {
            "time": datetime.now().strftime("%d-%m-%Y %H:%M"),
            "type": kind,
            "amount": amount,
            "balance": acc["balance"],
        }
    )


def logout():
    st.session_state.user = None
    st.session_state.role = None
    st.rerun()


# ---------------- Session ----------------
if "user" not in st.session_state:
    st.session_state.user = None
    st.session_state.role = None

accounts = load_accounts()

st.title("🏦 Bank System")


# ---------------- Not logged in ----------------
if st.session_state.user is None:
    tab_login, tab_create = st.tabs(["Login", "Create account"])

    with tab_login:
        acc_no = st.text_input("Account number (admin ke liye: admin)", key="login_acc")
        pin = st.text_input("PIN / Password", type="password", key="login_pin")

        if st.button("Login"):
            acc_no = acc_no.strip()
            admin_pw = get_admin_password()

            if acc_no.lower() == "admin":
                if admin_pw and pin == admin_pw:
                    st.session_state.user = "admin"
                    st.session_state.role = "admin"
                    st.rerun()
                else:
                    st.error("Galat admin password")
            elif acc_no in accounts:
                acc = accounts[acc_no]
                if hash_pin(pin, acc["salt"]) == acc["pin_hash"]:
                    st.session_state.user = acc_no
                    st.session_state.role = "user"
                    st.rerun()
                else:
                    st.error("Galat account number ya PIN")
            else:
                st.error("Galat account number ya PIN")

    with tab_create:
        name = st.text_input("Full name*", key="new_name")
        new_pin = st.text_input("PIN (4-8 digits)*", type="password", key="new_pin")
        confirm_pin = st.text_input("Confirm PIN*", type="password", key="new_pin2")
        deposit = st.number_input(
            "Opening deposit", min_value=0.0, step=100.0, key="new_dep"
        )

        if st.button("Create account"):
            if not name.strip():
                st.error("Naam likho")
            elif not (new_pin.isdigit() and 4 <= len(new_pin) <= 8):
                st.error("PIN 4 se 8 digits ka hona chahiye")
            elif new_pin != confirm_pin:
                st.error("PIN match nahi kar raha")
            else:
                while True:
                    acc_no = str(random.randint(10000000, 99999999))
                    if acc_no not in accounts:
                        break
                salt = os.urandom(8).hex()
                acc = {
                    "name": name.strip(),
                    "salt": salt,
                    "pin_hash": hash_pin(new_pin, salt),
                    "balance": float(deposit),
                    "history": [],
                }
                if deposit > 0:
                    add_txn(acc, "Opening deposit", float(deposit))
                accounts[acc_no] = acc
                save_accounts(accounts)
                st.success(f"Account ban gaya! Tumhara account number: {acc_no}")
                st.info("Ye number yaad rakho, login ke liye chahiye.")

    if not get_admin_password():
        st.caption("Admin login off hai (ADMIN_PASSWORD secret set nahi hai).")


# ---------------- Admin ----------------
elif st.session_state.role == "admin":
    col1, col2 = st.columns([3, 1])
    col1.subheader("Admin panel")
    if col2.button("Logout"):
        logout()

    if not accounts:
        st.info("Abhi koi account nahi hai.")
    else:
        st.write(f"Total accounts: {len(accounts)}")
        rows = [
            {"Account": k, "Name": v["name"], "Balance": v["balance"]}
            for k, v in accounts.items()
        ]
        st.dataframe(rows, use_container_width=True)

        st.divider()
        target = st.selectbox(
            "Account chuno",
            list(accounts.keys()),
            format_func=lambda k: f"{k} - {accounts[k]['name']}",
        )

        with st.expander("Transaction history dekho"):
            history = accounts[target]["history"]
            if history:
                st.dataframe(history, use_container_width=True)
            else:
                st.write("Koi transaction nahi.")

        confirm = st.checkbox("Haan, ye account delete karna hai")
        if st.button("Delete account", type="primary"):
            if confirm:
                del accounts[target]
                save_accounts(accounts)
                st.success("Account delete ho gaya")
                st.rerun()
            else:
                st.warning("Pehle checkbox tick karo")


# ---------------- Normal user ----------------
else:
    acc_no = st.session_state.user

    if acc_no not in accounts:
        # Account admin ne delete kar diya ya data reset ho gaya
        st.session_state.user = None
        st.session_state.role = None
        st.error("Ye account ab exist nahi karta.")
        st.stop()

    acc = accounts[acc_no]

    col1, col2 = st.columns([3, 1])
    col1.subheader(f"Welcome, {acc['name']}")
    if col2.button("Logout"):
        logout()

    st.caption(f"Account number: {acc_no}")
    st.metric("Balance", f"₹ {acc['balance']:,.2f}")

    tab_dep, tab_wd, tab_tr, tab_hist, tab_del = st.tabs(
        ["Deposit", "Withdraw", "Transfer", "History", "Delete"]
    )

    with tab_dep:
        amt = st.number_input("Amount", min_value=0.0, step=100.0, key="dep_amt")
        if st.button("Deposit"):
            if amt <= 0:
                st.error("Amount 0 se zyada hona chahiye")
            else:
                acc["balance"] += amt
                add_txn(acc, "Deposit", amt)
                save_accounts(accounts)
                st.success("Deposit ho gaya")
                st.rerun()

    with tab_wd:
        amt = st.number_input("Amount", min_value=0.0, step=100.0, key="wd_amt")
        if st.button("Withdraw"):
            if amt <= 0:
                st.error("Amount 0 se zyada hona chahiye")
            elif amt > acc["balance"]:
                st.error("Balance kam hai")
            else:
                acc["balance"] -= amt
                add_txn(acc, "Withdraw", amt)
                save_accounts(accounts)
                st.success("Withdraw ho gaya")
                st.rerun()

    with tab_tr:
        to_acc = st.text_input("Receiver account number", key="tr_acc").strip()
        amt = st.number_input("Amount", min_value=0.0, step=100.0, key="tr_amt")
        if st.button("Transfer"):
            if to_acc not in accounts or to_acc == acc_no:
                st.error("Receiver account galat hai")
            elif amt <= 0:
                st.error("Amount 0 se zyada hona chahiye")
            elif amt > acc["balance"]:
                st.error("Balance kam hai")
            else:
                other = accounts[to_acc]
                acc["balance"] -= amt
                other["balance"] += amt
                add_txn(acc, f"Transfer to {to_acc}", amt)
                add_txn(other, f"Received from {acc_no}", amt)
                save_accounts(accounts)
                st.success(f"{other['name']} ko transfer ho gaya")
                st.rerun()

    with tab_hist:
        if acc["history"]:
            st.dataframe(list(reversed(acc["history"])), use_container_width=True)
        else:
            st.write("Koi transaction nahi.")

    with tab_del:
        st.warning("Ye sirf tumhara apna account delete karega. Wapas nahi aayega.")
        pin_check = st.text_input("PIN dobara daalo", type="password", key="del_pin")
        if st.button("Mera account delete karo"):
            if hash_pin(pin_check, acc["salt"]) == acc["pin_hash"]:
                del accounts[acc_no]
                save_accounts(accounts)
                st.session_state.user = None
                st.session_state.role = None
                st.rerun()
            else:
                st.error("Galat PIN")

