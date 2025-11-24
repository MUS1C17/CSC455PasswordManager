import sys
import json
import sqlite3
import random

from Crypto.Protocol.KDF import scrypt
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

from PyQt5.QtWidgets import (
    QApplication, QWidget, QDialog, QVBoxLayout, QHBoxLayout,
    QLabel, QLineEdit, QPushButton, QMessageBox, QTableWidget,
    QTableWidgetItem, QHeaderView, QFormLayout, QFrame, QAbstractButton
)
from PyQt5.QtCore import Qt

DB_FILE = "PasswordManager.db"

def get_db():
    conn = sqlite3.connect(DB_FILE)
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA foreign_keys=ON;")
    return conn

def vault_exists():
    conn = get_db()
    cur = conn.execute("SELECT COUNT(*) FROM meta;")
    exists = cur.fetchone()[0] > 0
    conn.close()
    return exists


def derive_kek(master_password: str, salt: bytes) -> bytes:
    # 32-byte AES-256 key from password
    return scrypt(master_password.encode("utf-8"), salt, 32, N=2**15, r=8, p=1)

def create_vault(master_password: str) -> bytes:
    """
    Creates vault, generates MEK, wraps it with KEK, stores in meta.
    Returns MEK in memory.
    """
    if vault_exists():
        raise RuntimeError("Vault already exists.")

    salt = get_random_bytes(16)
    kek = derive_kek(master_password, salt)
    mek = get_random_bytes(32)

    cipher = AES.new(kek, AES.MODE_GCM)
    wrapped_mek, mek_tag = cipher.encrypt_and_digest(mek)
    mek_nonce = cipher.nonce

    conn = get_db()
    conn.execute(
        "INSERT INTO meta (id, kdf, salt, wrapped_mek, mek_nonce, mek_tag) VALUES (1, ?, ?, ?, ?, ?);",
        ("scrypt", salt, wrapped_mek, mek_nonce, mek_tag),
    )
    conn.commit()
    conn.close()
    return mek

def unlock_vault(master_password: str) -> bytes:
    conn = get_db()
    row = conn.execute(
        "SELECT kdf, salt, wrapped_mek, mek_nonce, mek_tag FROM meta WHERE id=1;"
    ).fetchone()
    conn.close()

    if not row:
        raise RuntimeError("Vault is not initialized.")

    kdf_name, salt, wrapped_mek, mek_nonce, mek_tag = row
    if kdf_name != "scrypt":
        raise RuntimeError("Unsupported KDF.")

    kek = derive_kek(master_password, salt)
    cipher = AES.new(kek, AES.MODE_GCM, nonce=mek_nonce)
    try:
        mek = cipher.decrypt_and_verify(wrapped_mek, mek_tag)
    except ValueError:
        raise RuntimeError("Incorrect master password or vault corrupted.")
    return mek

def encrypt_entry(mek: bytes, title: str, username: str, password: str, notes: str = ""):
    """
    Encrypts an entry payload with MEK, returns (nonce, tag, ciphertext).
    """
    payload = {
        "title": title,
        "username": username,
        "password": password,
        "notes": notes,
    }
    data = json.dumps(payload).encode("utf-8")

    cipher = AES.new(mek, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    nonce = cipher.nonce
    return nonce, tag, ciphertext

def decrypt_entry(mek: bytes, nonce: bytes, tag: bytes, ciphertext: bytes):
    """
    Decrypts a single entry with MEK, returns dict {title, username, password, notes}.
    """
    cipher = AES.new(mek, AES.MODE_GCM, nonce=nonce)
    plain = cipher.decrypt_and_verify(ciphertext, tag)
    obj = json.loads(plain.decode("utf-8"))
    obj.setdefault("username", "")
    obj.setdefault("notes", "")
    return obj

def add_entry_to_db(mek: bytes, title: str, username: str, password: str, notes: str = ""):
    nonce, tag, ciphertext = encrypt_entry(mek, title, username, password, notes)
    conn = get_db()
    conn.execute(
        "INSERT INTO entries (nonce, tag, ciphertext) VALUES (?, ?, ?);",
        (nonce, tag, ciphertext),
    )
    conn.commit()
    conn.close()

def update_entry_in_db(mek: bytes, entry_id: int, title: str, username: str, password: str, notes: str = ""):
    nonce, tag, ciphertext = encrypt_entry(mek, title, username, password, notes)
    conn = get_db()
    conn.execute(
        "UPDATE entries SET nonce=?, tag=?, ciphertext=?, updated_at=strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE id=?;",
        (nonce, tag, ciphertext, entry_id),
    )
    conn.commit()
    conn.close()

def delete_entry_from_db(entry_id: int):
    conn = get_db()
    conn.execute("DELETE FROM entries WHERE id=?;", (entry_id,))
    conn.commit()
    conn.close()

def load_entries(mek: bytes):
    """
    Returns a list of (id, title, username, password) for display/use.
    Password is not shown in UI, but kept in memory to support copy.
    """
    conn = get_db()
    rows = conn.execute(
        "SELECT id, nonce, tag, ciphertext FROM entries ORDER BY created_at DESC;"
    ).fetchall()
    conn.close()

    result = []
    for id_, nonce, tag, ct in rows:
        try:
            item = decrypt_entry(mek, nonce, tag, ct)
            title = item.get("title", "")
            username = item.get("username", "")
            password = item.get("password", "")
            result.append((id_, title, username, password))
        except Exception:
            result.append((id_, "<corrupted>", "", ""))  # no password shown
    return result

class LoginDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.mek = None  # will hold MEK on success

        self.setWindowTitle("Password Vault")
        self.setModal(True)
        self.resize(800, 600)  # bigger by default

        outer_layout = QVBoxLayout(self)
        outer_layout.setContentsMargins(24, 24, 24, 24)

        # Card frame in the middle
        card = QFrame()
        card.setObjectName("LoginCard")
        card_layout = QVBoxLayout(card)
        card_layout.setContentsMargins(24, 24, 24, 24)
        card_layout.setSpacing(16)

        outer_layout.addStretch(1)
        outer_layout.addWidget(card, alignment=Qt.AlignCenter)
        outer_layout.addStretch(1)

        # Title + subtitle
        self.title_label = QLabel()
        self.title_label.setAlignment(Qt.AlignCenter)
        self.title_label.setStyleSheet("font-size: 18px; font-weight: 600;")

        self.subtitle_label = QLabel()
        self.subtitle_label.setAlignment(Qt.AlignCenter)
        self.subtitle_label.setWordWrap(False)
        self.subtitle_label.setStyleSheet("color: #9ca3af; font-size: 11px; padding: 4px;")

        card_layout.addWidget(self.title_label)
        card_layout.addWidget(self.subtitle_label)

        # Password input
        self.pw_edit = QLineEdit()
        self.pw_edit.setEchoMode(QLineEdit.Password)
        self.pw_edit.setPlaceholderText("Enter master password")
        card_layout.addWidget(self.pw_edit)

        # Buttons row
        btn_layout = QHBoxLayout()
        btn_layout.addStretch(1)
        self.ok_btn = QPushButton()
        self.cancel_btn = QPushButton("Cancel")
        btn_layout.addWidget(self.cancel_btn)
        btn_layout.addWidget(self.ok_btn)
        card_layout.addLayout(btn_layout)

        self.cancel_btn.clicked.connect(self.reject)

        # Configure depending on whether vault exists
        if vault_exists():
            self.title_label.setText("Unlock your vault")
            self.subtitle_label.setText(
                "Enter your master password to access your saved logins."
            )
            self.ok_btn.setText("Unlock")
            self.ok_btn.clicked.connect(self.unlock_clicked)
        else:
            self.title_label.setText("Create your vault")
            self.subtitle_label.setText(
                "Set a master password to protect all your usernames and passwords.\n"
                "If you forget it, your data cannot be recovered."
            )
            self.ok_btn.setText("Create Vault")
            self.ok_btn.clicked.connect(self.create_clicked)

    def create_clicked(self):
        pw = self.pw_edit.text()
        if not pw:
            QMessageBox.warning(self, "Error", "Password cannot be empty.")
            return
        try:
            self.mek = create_vault(pw)
            QMessageBox.information(self, "Vault", "Vault created and unlocked.")
            self.accept()
        except Exception as e:
            QMessageBox.critical(self, "Error", str(e))

    def unlock_clicked(self):
        pw = self.pw_edit.text()
        if not pw:
            QMessageBox.warning(self, "Error", "Password cannot be empty.")
            return
        try:
            self.mek = unlock_vault(pw)
            self.accept()
        except Exception as e:
            QMessageBox.critical(self, "Error", str(e))

class EntryDialog(QDialog):
    def __init__(self, parent=None, title="", username="", password=""):
        super().__init__(parent)
        self.setWindowTitle("Entry")
        self.setModal(True)

        layout = QVBoxLayout(self)

        form = QFormLayout()
        layout.addLayout(form)

        self.title_edit = QLineEdit(title)
        self.username_edit = QLineEdit(username)
        self.password_edit = QLineEdit(password)
        self.password_edit.setEchoMode(QLineEdit.Password)

        form.addRow("Title:", self.title_edit)
        form.addRow("Username:", self.username_edit)
        form.addRow("Password:", self.password_edit)

        btn_layout = QHBoxLayout()
        layout.addLayout(btn_layout)

        self.ok_btn = QPushButton("Save")
        self.cancel_btn = QPushButton("Cancel")
        btn_layout.addWidget(self.ok_btn)
        btn_layout.addWidget(self.cancel_btn)

        self.ok_btn.clicked.connect(self.accept)
        self.cancel_btn.clicked.connect(self.reject)

        gen_btn_layout = QHBoxLayout()
        layout.addLayout(gen_btn_layout)

        self.generate_password_btn = QPushButton("Generate Password")
        gen_btn_layout.addWidget(self.generate_password_btn)
        self.generate_password_btn.clicked.connect(self.generate_password)

    def generate_password(self):
        # secure version of random
        rng = random.SystemRandom()
        possible_characters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+"

        random_password = ""
    
        # randomize until we get a password that fits most requirements
        while True:
            random_password = ''.join(rng.choice(possible_characters) for _ in range(32))
            if (any(c.islower() for c in random_password) and
                any(c.isupper() for c in random_password) and
                any(c.isdigit() for c in random_password) and
                any(c in "!@#$%^&*()-_=+" for c in random_password)):
                break  

        self.password_edit.setText(random_password)

    def get_values(self):
        return (
            self.title_edit.text().strip(),
            self.username_edit.text().strip(),
            self.password_edit.text().strip(),
        )

class MainWindow(QWidget):
    def __init__(self, mek: bytes):
        super().__init__()
        self.mek = mek
        self.entries = []  # list of (id, title, username, password)

        self.setWindowTitle("Simple Password Vault")
        self.resize(800, 600)

        main_layout = QVBoxLayout(self)

        # Top buttons
        btn_layout = QHBoxLayout()
        main_layout.addLayout(btn_layout)

        self.add_btn = QPushButton("Add Entry")
        self.edit_btn = QPushButton("Edit Entry")
        self.del_btn = QPushButton("Delete Entry")
        self.copy_user_btn = QPushButton("Copy Username")
        self.copy_pass_btn = QPushButton("Copy Password")

        btn_layout.addWidget(self.add_btn)
        btn_layout.addWidget(self.edit_btn)
        btn_layout.addWidget(self.del_btn)
        btn_layout.addStretch(1)
        btn_layout.addWidget(self.copy_user_btn)
        btn_layout.addWidget(self.copy_pass_btn)

        # Table
        self.table = QTableWidget(0, 2)
        self.table.setHorizontalHeaderLabels(["Title", "Username"])
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        main_layout.addWidget(self.table)

        # Connect buttons
        self.add_btn.clicked.connect(self.add_entry)
        self.edit_btn.clicked.connect(self.edit_entry)
        self.del_btn.clicked.connect(self.delete_entry)
        self.copy_user_btn.clicked.connect(self.copy_username)
        self.copy_pass_btn.clicked.connect(self.copy_password)

        self.reload_entries()

    def reload_entries(self):
        self.entries = load_entries(self.mek)
        self.table.setRowCount(0)
        for row_idx, (id_, title, username, _password) in enumerate(self.entries):
            self.table.insertRow(row_idx)
            self.table.setItem(row_idx, 0, QTableWidgetItem(title))
            self.table.setItem(row_idx, 1, QTableWidgetItem(username))

    def get_selected_entry(self):
        row = self.table.currentRow()
        if row < 0 or row >= len(self.entries):
            return None
        return self.entries[row]

    def add_entry(self):
        dlg = EntryDialog(self)
        if dlg.exec_() == QDialog.Accepted:
            title, username, password = dlg.get_values()
            if not title or not password:
                QMessageBox.warning(self, "Error", "Title and password are required.")
                return
            try:
                add_entry_to_db(self.mek, title, username, password)
                self.reload_entries()
            except Exception as e:
                QMessageBox.critical(self, "Error", str(e))

    def edit_entry(self):
        selected = self.get_selected_entry()
        if not selected:
            QMessageBox.information(self, "Edit", "Select an entry first.")
            return
        entry_id, title, username, password = selected

        dlg = EntryDialog(self, title=title, username=username, password=password)
        if dlg.exec_() == QDialog.Accepted:
            new_title, new_username, new_password = dlg.get_values()
            if not new_title or not new_password:
                QMessageBox.warning(self, "Error", "Title and password are required.")
                return
            try:
                update_entry_in_db(self.mek, entry_id, new_title, new_username, new_password)
                self.reload_entries()
            except Exception as e:
                QMessageBox.critical(self, "Error", str(e))

    def delete_entry(self):
        selected = self.get_selected_entry()
        if not selected:
            QMessageBox.information(self, "Delete", "Select an entry first.")
            return
        entry_id, title, _, _ = selected
        reply = QMessageBox.question(
            self,
            "Delete",
            f"Delete entry '{title}'?",
            QMessageBox.Yes | QMessageBox.No
        )
        if reply == QMessageBox.Yes:
            try:
                delete_entry_from_db(entry_id)
                self.reload_entries()
            except Exception as e:
                QMessageBox.critical(self, "Error", str(e))

    def copy_username(self):
        selected = self.get_selected_entry()
        if not selected:
            QMessageBox.information(self, "Copy Username", "Select an entry first.")
            return
        _, _, username, _ = selected
        if not username:
            QMessageBox.information(self, "Copy Username", "No username set.")
            return
        QApplication.clipboard().setText(username)
        QMessageBox.information(self, "Copy Username", "Username copied to clipboard.")

    def copy_password(self):
        selected = self.get_selected_entry()
        if not selected:
            QMessageBox.information(self, "Copy Password", "Select an entry first.")
            return
        _, title, _, password = selected
        if not password or title == "<corrupted>":
            QMessageBox.warning(self, "Copy Password", "Password unavailable.")
            return
        QApplication.clipboard().setText(password)
        QMessageBox.information(self, "Copy Password", "Password copied to clipboard.")

# ---------- MAIN ----------

def main():
    app = QApplication(sys.argv)

    # simple dark-ish theme
    app.setStyleSheet("""
        QWidget {
            background-color: #0f172a;
            color: #e5e7eb;
            font-family: Segoe UI, sans-serif;
            font-size: 10pt;
        }
        QFrame#LoginCard {
            background-color: #020617;
            border: 1px solid #334155;
            border-radius: 12px;
        }
        QLineEdit, QTableWidget {
            background-color: #020617;
            border: 1px solid #334155;
            border-radius: 4px;
            padding: 4px;
            color: #e5e7eb;
        }
        QTableView QTableCornerButton::section {
            background-color: #020617; 
            border: 1px solid black;
        }
        QHeaderView::section {
            background-color: #020617;
            color: #9ca3af;
            padding: 4px;
            border: none;
        }
        QPushButton {
            background-color: #2563eb;
            color: white;
            border-radius: 6px;
            padding: 6px 12px;
        }
        QPushButton:hover {
            background-color: #1d4ed8;
        }
        QPushButton:disabled {
            background-color: #1f2933;
            color: #6b7280;
        }
        QTableWidget::item:selected {
            background-color: #1d4ed8;
        }
    """)

    login = LoginDialog()
    if login.exec_() != QDialog.Accepted or login.mek is None:
        sys.exit(0)

    window = MainWindow(login.mek)
    window.show()

    sys.exit(app.exec_())

if __name__ == "__main__":
    main()
