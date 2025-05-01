import streamlit as st
import hashlib
import base64
from cryptography.fernet import Fernet

# Initialize session state
if "stored_data" not in st.session_state:
    st.session_state.stored_data = {}  # In-memory storage
if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0
if "is_authenticated" not in st.session_state:
    st.session_state.is_authenticated = True

# Helper functions
def hash_passkey(passkey):
    """Hash the passkey using SHA-256."""
    return hashlib.sha256(passkey.encode()).hexdigest()

def generate_key(passkey):
    """Generate a Fernet key from the hashed passkey."""
    hashed_passkey = hash_passkey(passkey)
    # Take the first 32 characters from the hashed passkey to create a Fernet-compatible key
    key = hashed_passkey[:32]
    # Encode the key in URL-safe base64 format
    return base64.urlsafe_b64encode(key.encode())

def encrypt_data(data, passkey):
    """Encrypt data using Fernet."""
    key = generate_key(passkey)
    cipher = Fernet(key)
    return cipher.encrypt(data.encode())

def decrypt_data(encrypted_data, passkey):
    """Decrypt data using Fernet."""
    key = generate_key(passkey)
    cipher = Fernet(key)
    return cipher.decrypt(encrypted_data).decode()

def login_page():
    """Display the login page for reauthorization."""
    st.error("Reauthorization required! Please log in again.")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")
    if st.button("Login"):
        if username == "admin" and password == "password":
            st.session_state.failed_attempts = 0
            st.session_state.is_authenticated = True
            st.success("Logged in successfully!")
        else:
            st.error("Invalid credentials!")

# Main pages
def home_page():
    """Home page with options to store or retrieve data."""
    st.title("Secure Data Storage System")
    st.write("Welcome to the secure data storage system!")
    option = st.radio("Choose an action", ["Store Data", "Retrieve Data"])
    if option == "Store Data":
        insert_data_page()
    elif option == "Retrieve Data":
        retrieve_data_page()

def insert_data_page():
    """Page to store data securely."""
    st.header("Store Data")
    text = st.text_area("Enter the text you want to store")
    passkey = st.text_input("Enter a unique passkey", type="password")
    if st.button("Store"):
        if text and passkey:
            hashed_passkey = hash_passkey(passkey)
            encrypted_text = encrypt_data(text, passkey)
            st.session_state.stored_data[hashed_passkey] = {"encrypted_text": encrypted_text}
            st.success("Data stored securely!")
        else:
            st.error("Both text and passkey are required!")

def retrieve_data_page():
    """Page to retrieve data securely."""
    st.header("Retrieve Data")
    passkey = st.text_input("Enter your passkey", type="password")
    if st.button("Retrieve"):
        if st.session_state.failed_attempts >= 3:
            st.session_state.is_authenticated = False
            login_page()
        elif passkey:
            hashed_passkey = hash_passkey(passkey)
            if hashed_passkey in st.session_state.stored_data:
                try:
                    encrypted_text = st.session_state.stored_data[hashed_passkey]["encrypted_text"]
                    decrypted_text = decrypt_data(encrypted_text, passkey)
                    st.success("Data retrieved successfully!")
                    st.text_area("Your Decrypted Data", decrypted_text, disabled=True)
                except Exception:
                    st.session_state.failed_attempts += 1
                    st.error(f"Incorrect passkey! Failed attempts: {st.session_state.failed_attempts}")
            else:
                st.session_state.failed_attempts += 1
                st.error(f"Passkey not found! Failed attempts: {st.session_state.failed_attempts}")
        else:
            st.error("Passkey is required!")

# App Routing
if not st.session_state.is_authenticated:
    login_page()
else:
    home_page()
