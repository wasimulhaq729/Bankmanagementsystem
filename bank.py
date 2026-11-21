# Bank Account Management System - Streamlit version
# Uses: functions, loops, if/else, file handling, classes and objects
# Run with:  streamlit run bank_app.py

import streamlit as st

FILE_NAME = "accounts.txt"


# ---------- PERSON 1: Account class ----------
class Account:
    def __init__(self, acc_no, name, balance=0.0):
        self.acc_no = acc_no
        self.name = name
        self.balance = balance

    def deposit(self, amount):
        if amount <= 0:
            return False
        self.balance += amount
        return True

    def withdraw(self, amount):
        if amount <= 0 or amount > self.balance:
            return False
        self.balance -= amount
        return True


# ---------- PERSON 2: Bank class ----------
class Bank:
    def __init__(self):
        self.accounts = []

    def create_account(self, name, initial_balance):
        if len(self.accounts) == 0:
            acc_no = 1001
        else:
            acc_no = max(acc.acc_no for acc in self.accounts) + 1
        account = Account(acc_no, name, initial_balance)
        self.accounts.append(account)
        return account

    def find_account(self, acc_no):
        for account in self.accounts:
            if account.acc_no == acc_no:
                return account
        return None

    def transfer(self, from_no, to_no, amount):
        sender = self.find_account(from_no)
        receiver = self.find_account(to_no)
        if sender is None or receiver is None:
            return False, "Account not found."
        if from_no == to_no:
            return False, "Cannot transfer to the same account."
        if not sender.withdraw(amount):
            return False, "Invalid amount or insufficient balance."
        receiver.deposit(amount)
        return True, "Transfer successful."

    def delete_account(self, acc_no):
        account = self.find_account(acc_no)
        if account is None:
            return False
        self.accounts.remove(account)
        return True


# ---------- PERSON 3: File handling ----------
def save_data(bank):
    file = open(FILE_NAME, "w")
    for acc in bank.accounts:
        file.write(f"{acc.acc_no},{acc.name},{acc.balance}\n")
    file.close()


def load_data(bank):
    open(FILE_NAME, "a").close()  # creates the file if it doesn't exist
    file = open(FILE_NAME, "r")
    for line in file:
        line = line.strip()
        if line == "":
            continue
        parts = line.split(",")
        bank.accounts.append(Account(int(parts[0]), parts[1], float(parts[2])))
    file.close()


# ---------- PERSON 4: Streamlit interface ----------
def get_bank():
    # Streamlit reruns the script on every click, so keep the bank in session_state
    if "bank" not in st.session_state:
        bank = Bank()
        load_data(bank)
        st.session_state.bank = bank
    return st.session_state.bank


def pick_account(bank, label, key):
    if len(bank.accounts) == 0:
        st.warning("No accounts yet. Create one first.")
        return None
    options = [acc.acc_no for acc in bank.accounts]
    return st.selectbox(
        label,
        options,
        format_func=lambda n: f"{n} - {bank.find_account(n).name}",
        key=key,
    )


def page_create(bank):
    st.subheader("Create Account")
    name = st.text_input("Account holder name")
    amount = st.number_input("Opening balance", min_value=0.0, step=100.0, format="%.2f")
    if st.button("Create account"):
        if name.strip() == "":
            st.error("Please enter a name.")
        else:
            acc = bank.create_account(name.strip(), amount)
            save_data(bank)
            st.success(f"Account created. Account number: {acc.acc_no}")


def page_deposit(bank):
    st.subheader("Deposit")
    acc_no = pick_account(bank, "Select account", "dep_acc")
    if acc_no is None:
        return
    amount = st.number_input("Amount to deposit", min_value=0.0, step=100.0, format="%.2f")
    if st.button("Deposit"):
        acc = bank.find_account(acc_no)
        if acc.deposit(amount):
            save_data(bank)
            st.success(f"Deposited. New balance: {acc.balance:.2f}")
        else:
            st.error("Invalid amount.")


def page_withdraw(bank):
    st.subheader("Withdraw")
    acc_no = pick_account(bank, "Select account", "wd_acc")
    if acc_no is None:
        return
    amount = st.number_input("Amount to withdraw", min_value=0.0, step=100.0, format="%.2f")
    if st.button("Withdraw"):
        acc = bank.find_account(acc_no)
        if acc.withdraw(amount):
            save_data(bank)
            st.success(f"Withdrawn. New balance: {acc.balance:.2f}")
        else:
            st.error("Invalid amount or insufficient balance.")


def page_transfer(bank):
    st.subheader("Transfer")
    from_no = pick_account(bank, "From account", "tr_from")
    to_no = pick_account(bank, "To account", "tr_to")
    if from_no is None or to_no is None:
        return
    amount = st.number_input("Amount", min_value=0.0, step=100.0, format="%.2f")
    if st.button("Transfer"):
        done, message = bank.transfer(from_no, to_no, amount)
        if done:
            save_data(bank)
            st.success(message)
        else:
            st.error(message)


def page_balance(bank):
    st.subheader("Check Balance")
    acc_no = pick_account(bank, "Select account", "bal_acc")
    if acc_no is None:
        return
    acc = bank.find_account(acc_no)
    st.metric(label=f"{acc.name} (Acc {acc.acc_no})", value=f"{acc.balance:.2f}")


def page_show_all(bank):
    st.subheader("All Accounts")
    if len(bank.accounts) == 0:
        st.info("No accounts yet.")
        return
    rows = []
    for acc in bank.accounts:
        rows.append({"Account No": acc.acc_no, "Name": acc.name, "Balance": round(acc.balance, 2)})
    st.table(rows)


def page_delete(bank):
    st.subheader("Delete Account")
    acc_no = pick_account(bank, "Select account", "del_acc")
    if acc_no is None:
        return
    if st.button("Delete account"):
        bank.delete_account(acc_no)
        save_data(bank)
        st.success("Account deleted.")
        st.rerun()


def main():
    st.set_page_config(page_title="Bank System", page_icon="🏦")
    st.title("🏦 Bank Account Management System")
    bank = get_bank()

    menu = [
        "Create Account",
        "Deposit",
        "Withdraw",
        "Transfer",
        "Check Balance",
        "Show All Accounts",
        "Delete Account",
    ]
    choice = st.sidebar.radio("Menu", menu)

    if choice == "Create Account":
        page_create(bank)
    elif choice == "Deposit":
        page_deposit(bank)
    elif choice == "Withdraw":
        page_withdraw(bank)
    elif choice == "Transfer":
        page_transfer(bank)
    elif choice == "Check Balance":
        page_balance(bank)
    elif choice == "Show All Accounts":
        page_show_all(bank)
    elif choice == "Delete Account":
        page_delete(bank)


main()
