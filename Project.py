# Password Manager: Comprehensive Implementation

# Required Libraries
import os
import sqlite3
import bcrypt
import secrets
import string
from hashlib import pbkdf2_hmac
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import tkinter as tk
from tkinter import messagebox

# Configuration Settings
DATABASE_FILE = "passwords.db"
MASTER_PASSWORD_HASH_FILE = "master_password.hash"
SECURITY_QUESTION_FILE = "security_question.txt"

# Key Management and Encryption Utilities
class EncryptionManager:
    def __init__(self, key):
        self.key = key

    @staticmethod
    def generate_key_from_password(password, salt):
        return pbkdf2_hmac("sha256", password.encode(), salt, 100000, dklen=32)

    def encrypt(self, data):
        cipher = AES.new(self.key, AES.MODE_GCM)
        ciphertext, tag = cipher.encrypt_and_digest(data.encode())
        return cipher.nonce, ciphertext, tag

    def decrypt(self, nonce, ciphertext, tag):
        cipher = AES.new(self.key, AES.MODE_GCM, nonce=nonce)
        return cipher.decrypt_and_verify(ciphertext, tag).decode()

# Database Initialization
def initialize_database():
    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS passwords (
                        id INTEGER PRIMARY KEY,
                        service TEXT NOT NULL,
                        username TEXT NOT NULL,
                        password BLOB NOT NULL,
                        nonce BLOB NOT NULL,
                        tag BLOB NOT NULL,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                      )''')
    conn.commit()
    conn.close()

# Password Generation
def generate_password(length=16):
    alphabet = string.ascii_letters + string.digits + string.punctuation
    return ''.join(secrets.choice(alphabet) for _ in range(length))

# Master Password Management
def set_master_password():
    password = input("Set a master password: ").strip()
    hashed_password = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
    with open(MASTER_PASSWORD_HASH_FILE, "wb") as file:
        file.write(hashed_password)
    
    security_question = input("Set a security question (to retrieve your password if forgotten): ").strip()
    security_answer = input("Set the answer to the security question: ").strip()
    hashed_answer = bcrypt.hashpw(security_answer.encode(), bcrypt.gensalt())
    with open(SECURITY_QUESTION_FILE, "w") as file:
        file.write(security_question + "\n")
        file.write(hashed_answer.decode())
    
    print("Master password and security question set.")

def retrieve_master_password():
    if not os.path.exists(SECURITY_QUESTION_FILE):
        print("No security question found. Cannot retrieve master password.")
        return None

    with open(SECURITY_QUESTION_FILE, "r") as file:
        security_question = file.readline().strip()
        stored_hash = file.readline().strip().encode()

    print(f"Security Question: {security_question}")
    answer = input("Enter the answer to the security question: ").strip()
    if bcrypt.checkpw(answer.encode(), stored_hash):
        print("Answer correct. You can now reset your master password.")
        set_master_password()
        return True
    else:
        print("Incorrect answer. Cannot retrieve master password.")
        return False

def verify_master_password():
    if not os.path.exists(MASTER_PASSWORD_HASH_FILE):
        print("No master password found. Please set it up.")
        set_master_password()
        for _ in range(3):
            password = input("Re-enter the master password you just set: ").strip()
            with open(MASTER_PASSWORD_HASH_FILE, "rb") as file:
                stored_hash = file.read()
            if bcrypt.checkpw(password.encode(), stored_hash):
                print("Master password confirmed.")
                return password
            else:
                print("Passwords do not match. Try again.")
        print("Failed to confirm the master password. Exiting.")
        return None

    with open(MASTER_PASSWORD_HASH_FILE, "rb") as file:
        stored_hash = file.read()

    for _ in range(3):
        password = input("Enter master password: ").strip()
        if bcrypt.checkpw(password.encode(), stored_hash):
            print("Access granted.")
            return password
        else:
            print("Invalid password. Try again.")
    
    print("Access denied.")
    if input("Forgot your master password? (yes/no): ").strip().lower() == "yes":
        if retrieve_master_password():
            for _ in range(3):
                password = input("Re-enter the new master password you just set: ").strip()
                with open(MASTER_PASSWORD_HASH_FILE, "rb") as file:
                    stored_hash = file.read()
                if bcrypt.checkpw(password.encode(), stored_hash):
                    print("Master password confirmed.")
                    return password
                else:
                    print("Passwords do not match. Try again.")
            print("Failed to confirm the new master password. Exiting.")
            return None
    return None

# GUI Implementation
def launch_gui(encryption_manager):
    def add_password():
        service = service_entry.get()
        username = username_entry.get()
        password = password_entry.get()

        if not service or not username or not password:
            messagebox.showerror("Error", "All fields are required.")
            return

        nonce, ciphertext, tag = encryption_manager.encrypt(password)

        conn = sqlite3.connect(DATABASE_FILE)
        cursor = conn.cursor()
        cursor.execute('''INSERT INTO passwords (service, username, password, nonce, tag) 
                          VALUES (?, ?, ?, ?, ?)''', 
                       (service, username, ciphertext, nonce, tag))
        conn.commit()
        conn.close()

        messagebox.showinfo("Success", "Password added successfully!")
        service_entry.delete(0, tk.END)
        username_entry.delete(0, tk.END)
        password_entry.delete(0, tk.END)

    def view_passwords():
        conn = sqlite3.connect(DATABASE_FILE)
        cursor = conn.cursor()
        cursor.execute("SELECT service, username, password, nonce, tag FROM passwords")
        records = cursor.fetchall()
        conn.close()

        view_window = tk.Toplevel(root)
        view_window.title("Saved Passwords")

        for record in records:
            service, username, ciphertext, nonce, tag = record
            try:
                decrypted_password = encryption_manager.decrypt(nonce, ciphertext, tag)
            except Exception:
                decrypted_password = "[Decryption Failed]"

            tk.Label(view_window, text=f"Service: {service}, Username: {username}, Password: {decrypted_password}").pack()

    root = tk.Tk()
    root.title("Password Manager")

    tk.Label(root, text="Service").pack()
    service_entry = tk.Entry(root)
    service_entry.pack()

    tk.Label(root, text="Username").pack()
    username_entry = tk.Entry(root)
    username_entry.pack()

    tk.Label(root, text="Password").pack()
    password_entry = tk.Entry(root, show="*")
    password_entry.pack()

    add_button = tk.Button(root, text="Add Password", command=add_password)
    add_button.pack()

    view_button = tk.Button(root, text="View Passwords", command=view_passwords)
    view_button.pack()

    root.mainloop()

def reset_stored_data():
    if os.path.exists(DATABASE_FILE):
        os.remove(DATABASE_FILE)
        print(f"{DATABASE_FILE} has been deleted.")
    if os.path.exists(MASTER_PASSWORD_HASH_FILE):
        os.remove(MASTER_PASSWORD_HASH_FILE)
        print(f"{MASTER_PASSWORD_HASH_FILE} has been deleted.")
    if os.path.exists(SECURITY_QUESTION_FILE):
        os.remove(SECURITY_QUESTION_FILE)
        print(f"{SECURITY_QUESTION_FILE} has been deleted.")
    print("All stored data has been reset.")

# Main Execution
if __name__ == "__main__":
    initialize_database()

    if input("Do you want to no all stored data? (yes/no): ").strip().lower() == "yes":
        reset_stored_data()
        exit()

    master_password = verify_master_password()
    if not master_password:
        exit()

    salt = os.urandom(16)
    encryption_key = EncryptionManager.generate_key_from_password(master_password, salt)
    encryption_manager = EncryptionManager(encryption_key)

    launch_gui(encryption_manager)
