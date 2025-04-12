import streamlit as st
import hashlib
from cryptography.fernet import Fernet

# Generate Fernet key (use env var or secure file in production)
KEY = Fernet.generate_key()
cipher = Fernet(KEY)

# In-memory storage
if "stored_data" not in st.session_state:
    st.session_state.stored_data = {}  # {encrypted_text: {"encrypted_text": ..., "passkey": ...}}
if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0
if "authorized" not in st.session_state:
    st.session_state.authorized = True  # Default true until 3 failures

# Hashing Function
def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

# Encrypt
def encrypt_data(text):
    return cipher.encrypt(text.encode()).decode()

# Decrypt
def decrypt_data(encrypted_text, passkey):
    hashed = hash_passkey(passkey)
    data = st.session_state.stored_data.get(encrypted_text)
    if data and data["passkey"] == hashed:
        st.session_state.failed_attempts = 0
        return cipher.decrypt(encrypted_text.encode()).decode()
    else:
        st.session_state.failed_attempts += 1
        return None

# Navigation
menu = ["Home", "Store Data", "Retrieve Data"]
if not st.session_state.authorized:
    menu = ["Login"]

choice = st.sidebar.selectbox("🔎 Navigation", menu)

# Pages
if choice == "Home":
    st.title("🔒 Secure Data Encryption System")
    st.markdown("Securely **store and retrieve encrypted data** using unique passkeys.")
    st.info("Use the sidebar to navigate between storing and retrieving your secrets.")

elif choice == "Store Data":
    st.title("📂 Store Data")
    text = st.text_area("Enter Data to Encrypt:")
    passkey = st.text_input("Enter Passkey:", type="password")

    if st.button("🔐 Encrypt & Store"):
        if text and passkey:
            encrypted_text = encrypt_data(text)
            hashed_pass = hash_passkey(passkey)
            st.session_state.stored_data[encrypted_text] = {
                "encrypted_text": encrypted_text,
                "passkey": hashed_pass
            }
            st.success("✅ Data encrypted and stored securely.")
            st.code(encrypted_text, language="text")
        else:
            st.error("❗ Both fields are required.")

elif choice == "Retrieve Data":
    st.title("🔍 Retrieve Data")
    if st.session_state.failed_attempts >= 3:
        st.warning("🔒 Too many failed attempts. Please login to continue.")
        st.session_state.authorized = False
        st.experimental_rerun()

    encrypted_input = st.text_area("Paste Encrypted Data:")
    passkey_input = st.text_input("Enter Passkey:", type="password")

    if st.button("🔓 Decrypt"):
        if encrypted_input and passkey_input:
            result = decrypt_data(encrypted_input, passkey_input)
            if result:
                st.success("✅ Data decrypted successfully:")
                st.code(result, language="text")
            else:
                attempts_left = 3 - st.session_state.failed_attempts
                st.error(f"❌ Incorrect passkey! Attempts left: {attempts_left}")
        else:
            st.error("❗ Both fields are required.")

elif choice == "Login":
    st.title("🔑 Reauthorization Required")
    master_password = st.text_input("Enter Master Password:", type="password")

    if st.button("Login"):
        if master_password == "admin123":
            st.session_state.failed_attempts = 0
            st.session_state.authorized = True
            st.success("✅ Login successful. Redirecting...")
            st.experimental_rerun()
        else:
            st.error("❌ Incorrect master password.")

# Footer
st.markdown(f"<footer style='text-align:center; margin-top: 20px;'><p>All Rights Reserved &copy; 2025 Ubaid-ur-Rehman</p></footer>", unsafe_allow_html=True)
