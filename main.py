import streamlit as st
import hashlib
from cryptography.fernet import Fernet

# Key generation (normally store securely)
KEY = Fernet.generate_key()
cipher = Fernet(KEY)

# In-memory data storage
stored_data = {}
failed_attempts = 0

# Hashing function
def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

# Encrypt data
def encrypt_data(text):
    return cipher.encrypt(text.encode()).decode()

# Decrypt data
def decrypt_data(encrypted_text, passkey):
    global failed_attempts
    hashed_passkey = hash_passkey(passkey)
    
    if encrypted_text in stored_data:
        if stored_data[encrypted_text]["passkey"] == hashed_passkey:
            failed_attempts = 0
            return cipher.decrypt(encrypted_text.encode()).decode()
    
    failed_attempts += 1
    return None

# Streamlit UI
st.title("🔐 Secure Data Encryption System")

# Sidebar menu
menu = ["Home", "Store Data", "Retrieve Data", "Login"]
choice = st.sidebar.selectbox("Menu", menu)

# Pages
if choice == "Home":
    st.subheader("🏠 Welcome")
    st.write("Is app se aap securely data store aur retrieve kar sakte hain.")

elif choice == "Store Data":
    st.subheader("📦 Store Your Data")
    user_text = st.text_area("Enter your text:")
    passkey = st.text_input("Set a Passkey:", type="password")

    if st.button("Encrypt & Save"):
        if user_text and passkey:
            encrypted = encrypt_data(user_text)
            hashed = hash_passkey(passkey)
            stored_data[encrypted] = {"encrypted_text": encrypted, "passkey": hashed}
            st.success("✅ Data Encrypted & Stored")
            st.code(encrypted, language="text")
        else:
            st.error("⚠️ Please enter both text and passkey.")

elif choice == "Retrieve Data":
    st.subheader("🔓 Retrieve Data")
    encrypted_input = st.text_area("Paste your encrypted text:")
    passkey = st.text_input("Enter your Passkey:", type="password")

    if st.button("Decrypt"):
        if encrypted_input and passkey:
            result = decrypt_data(encrypted_input, passkey)
            if result:
                st.success(f"✅ Your decrypted data: {result}")
            else:
                st.error(f"❌ Incorrect passkey. Attempts left: {3 - failed_attempts}")
                if failed_attempts >= 3:
                    st.warning("🔒 Too many attempts. Redirecting to Login.")
                    st.experimental_rerun()
        else:
            st.error("⚠️ Please fill both fields.")

elif choice == "Login":
    st.subheader("🔑 Reauthorization Required")
    master_pass = st.text_input("Enter Master Password:", type="password")

    if st.button("Login"):
        if master_pass == "admin123":
            failed_attempts = 0
            st.success("✅ Logged in! Go back to 'Retrieve Data'")
        else:
            st.error("❌ Incorrect master password.")
