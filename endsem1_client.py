import socket
import json
import uuid
import time
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend
from os import urandom

# --- CONFIGURATION ---
SERVER_HOST = '127.0.0.1'
SERVER_PORT = 9999
CLIENT_KEYS = {}
DOCTOR_ID = None
SERVER_RSA_HE_PUB_KEY = None
AUDITOR_RSA_PRIV_KEY = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)


# --- MOCKED CRYPTOGRAPHIC PRIMITIVES ---

def generate_key_pair(name):
    """Generates a placeholder key pair for the advanced schemes."""
    print(f"  [CRYPTO: MOCK] Generating {name} Key Pair...")
    # Return placeholder strings that are stored in the state
    return {
        "pub": f"PUBLIC_KEY_{name}_{str(uuid.uuid4())[:4]}",
        "priv": f"PRIVATE_KEY_{name}_{str(uuid.uuid4())[:4]}"
    }


def rsa_he_encrypt(amount, pub_key_str):
    """Mocks RSA-HE encryption for expense logging: E(amount)."""
    # In a real RSA-HE scheme, this uses complex modular exponentiation with the server's public key (n, g).
    print("  [CRYPTO: RSA-HE] Encrypting expense amount homomorphically...")
    return str(amount)  # Simple string conversion mock for demonstration


def paillier_encrypt(keyword, pub_key_str):
    """Mocks Paillier encryption for department search: E(keyword)."""
    # The Paillier public key (n, g) is used here.
    # The server performs E(D)*E(Q)^-1 using this ciphertext.
    print("  [CRYPTO: PAILLIER] Encrypting department keyword homomorphically...")
    # Assign a deterministic mock based on the keyword's length for search simulation
    return str(len(keyword) * 100 + sum(ord(c) for c in keyword))


def elgamal_sign(message, priv_key_str):
    """Mocks ElGamal signature generation."""
    # In a real system, this generates a non-repudiable signature (r, s)
    print("  [CRYPTO: ELGAMAL] Signing report hash...")

    # CORRECTED: Use the Hash object to finalize the digest
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(message.encode('utf-8'))
    return digest.finalize().hex()[:10]  # Mock the signature with the message hash (first 10 chars)


# --- KEY MANAGEMENT AND INITIALIZATION ---

def generate_all_keys():
    """Generates all required key pairs for a doctor."""
    rsa_priv = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    rsa_pub = rsa_priv.public_key()

    return {
        'rsa_priv': rsa_priv,
        'rsa_pub': rsa_pub,
        'elgamal': generate_key_pair("ELGAMAL"),
        'paillier': generate_key_pair("PAILLIER")
    }


def get_rsa_key_bytes(key_object, is_private=False):
    """Serializes RSA keys to strings for transfer."""
    if is_private:
        return key_object.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode('utf-8')
    else:
        return key_object.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')


# --- COMMUNICATION HELPER ---

def send_request(action, data=None):
    """Establishes a connection and sends a JSON request."""
    if data is None:
        data = {}

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((SERVER_HOST, SERVER_PORT))

            request = {'action': action, 'data': data}
            s.sendall(json.dumps(request).encode('utf-8'))

            # Receive response
            response_data = s.recv(16384).decode('utf-8')
            return json.loads(response_data)

    except ConnectionRefusedError:
        print("\n[ERROR] Server connection refused. Ensure server.py is running.")
        return None
    except Exception as e:
        print(f"\n[ERROR] Communication failed: {e}")
        return None


# --- DOCTOR FUNCTIONS ---

def doctor_register():
    """Registers the doctor and retrieves the server's RSA-HE public key."""
    global CLIENT_KEYS, DOCTOR_ID, SERVER_RSA_HE_PUB_KEY

    if DOCTOR_ID:
        print(f"\nAlready registered as Doctor {DOCTOR_ID}.")
        return

    print("\n--- Doctor Registration ---")
    dept = input("Enter your Department Name (e.g., Cardiology): ").strip()
    if not dept:
        print("Department name is required.")
        return

    # 1. Generate all keys
    CLIENT_KEYS = generate_all_keys()

    # 2. Encrypt department (Paillier)
    encrypted_dept = paillier_encrypt(dept, CLIENT_KEYS['paillier']['pub'])

    # 3. Compile public keys for server
    pub_keys_data = {
        'rsa': get_rsa_key_bytes(CLIENT_KEYS['rsa_pub']),
        'elgamal': CLIENT_KEYS['elgamal']['pub'],
        'paillier': CLIENT_KEYS['paillier']['pub']
    }

    # 4. Send registration request
    response = send_request('register', {
        'pub_keys': pub_keys_data,
        'encrypted_department': encrypted_dept,
        'department_name': dept  # For server logging/mocked search
    })

    if response and response['status'] == 'SUCCESS':
        DOCTOR_ID = response['data']['doctor_id']
        SERVER_RSA_HE_PUB_KEY = response['data']['rsa_he_pub_key']
        print(f"\n✅ Registration successful! Your ID is: {DOCTOR_ID}")
        print(f"Server HE Key: {SERVER_RSA_HE_PUB_KEY[:10]}...")
    else:
        print(f"❌ Registration failed: {response.get('message', 'Unknown error')}")


def doctor_submit_report():
    """Encrypts report content, encrypts the key, and signs the message."""
    if not DOCTOR_ID:
        print("\nPlease register first.")
        return

    print("\n--- Submit Medical Report ---")
    report_content = input("Enter report content (sensitive details): ").strip()
    if not report_content:
        print("Report content cannot be empty.")
        return

    # 1. AES Encryption (Authenticated Encryption of Content)
    aes_key = AESGCM.generate_key(bit_length=256)  # Ephemeral 256-bit key
    aesgcm = AESGCM(aes_key)
    nonce = urandom(12)
    # Encrypt content and tag
    # Prepending nonce to the encrypted content for easy extraction during decryption
    encrypted_content = (nonce + aesgcm.encrypt(nonce, report_content.encode('utf-8'), None)).hex()

    # 2. Key Transport (RSA Encryption of AES Key)
    # The client needs the server's RSA public key (not the HE key) for key transport.
    # Since we didn't send a separate RSA pub key in the mock, we use the Auditor's
    # RSA public key as a stand-in for the server's public key (for demonstration).
    server_rsa_pub_key = AUDITOR_RSA_PRIV_KEY.public_key()

    encrypted_aes_key = server_rsa_pub_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    ).hex()

    # 3. Digital Signature (ElGamal)
    timestamp = str(time.time())
    # Sign over metadata and a hash/preview of the encrypted content
    message_to_sign = f"{DOCTOR_ID}|{timestamp}|{encrypted_content[:50]}"
    signature = elgamal_sign(message_to_sign, CLIENT_KEYS['elgamal']['priv'])

    response = send_request('submit_report', {
        'doctor_id': DOCTOR_ID,
        'encrypted_aes_key': encrypted_aes_key,
        'encrypted_content': encrypted_content,
        'signature': signature,
        'timestamp': timestamp
    })

    if response and response['status'] == 'SUCCESS':
        print("\n✅ Report submitted securely and signed.")
    else:
        print(f"❌ Report submission failed: {response.get('message', 'Unknown error')}")


def doctor_log_expense():
    """Encrypts expense amount using the server's RSA-HE public key."""
    if not DOCTOR_ID or not SERVER_RSA_HE_PUB_KEY:
        print("\nPlease register first to get the server's HE key.")
        return

    print("\n--- Log Expense ---")
    try:
        amount = int(input("Enter expense amount (integer only): ").strip())
    except ValueError:
        print("Invalid amount.")
        return

    # 1. Homomorphic Encryption (RSA-HE)
    # The amount is encrypted such that the server can sum it with other encrypted amounts
    encrypted_amount = rsa_he_encrypt(amount, SERVER_RSA_HE_PUB_KEY)

    response = send_request('log_expense', {
        'doctor_id': DOCTOR_ID,
        'encrypted_amount': encrypted_amount,  # RSA-HE Ciphertext (mocked string)
        'timestamp': str(time.time())
    })

    if response and response['status'] == 'SUCCESS':
        print(f"\n✅ Expense of ${amount} logged. Stored as encrypted value: {encrypted_amount}")
    else:
        print(f"❌ Expense logging failed: {response.get('message', 'Unknown error')}")


# --- AUDITOR FUNCTIONS ---

def auditor_search_doctors():
    """Searches doctors by department keyword using Paillier HE."""
    print("\n--- Privacy-Preserving Doctor Search ---")
    search_keyword = input("Enter Department Keyword to search (e.g., 'Cardiology'): ").strip()
    if not search_keyword:
        print("Search keyword is required.")
        return

    # 1. Encrypt Search Keyword (Paillier)
    # The auditor uses the Paillier public key (mocked as any string, as the server handles the key logic)
    # We use a placeholder key string here to simulate E(Q)
    encrypted_keyword = paillier_encrypt(search_keyword, "PAILLIER_PLACEHOLDER_PUB_KEY")

    # 2. Send the encrypted keyword to the server
    response = send_request('audit_search_doctors', {
        'encrypted_keyword': encrypted_keyword
    })

    if response and response['status'] == 'SUCCESS':
        doctors = response['data']['matching_doctors']
        if doctors:
            print(f"\n✅ Found {len(doctors)} doctor(s) matching the encrypted keyword:")
            for doc_id in doctors:
                print(f"- {doc_id}")
        else:
            print("\n❌ No doctors matched the encrypted keyword.")
    else:
        print(f"❌ Search failed: {response.get('message', 'Unknown error')}")


def auditor_sum_expenses():
    """Performs homomorphic summation of expenses."""
    print("\n--- Privacy-Preserving Expense Summation ---")

    target = input("Enter Doctor ID to sum (or leave blank for all doctors): ").strip()

    response = send_request('audit_sum_expenses', {
        'doctor_id': target if target else None
    })

    if response and response['status'] == 'SUCCESS':
        data = response['data']
        print(f"\n✅ Homomorphic Summation Successful (Target: {'ALL' if not target else target}):")
        print(f"   - Total Encrypted Amount (HE Ciphertext): {data['total_encrypted_amount']}")
        print(f"   - Decrypted Sum (Server-side HE Decryption): ${data['total_decrypted_sum']}")
    else:
        print(f"❌ Summation failed: {response.get('message', 'Unknown error')}")


def auditor_audit_reports():
    """Lists and decrypts reports."""
    print("\n--- Report Audit ---")
    list_response = send_request('audit_list_reports')

    if not list_response or list_response['status'] != 'SUCCESS':
        print(f"❌ Failed to list reports: {list_response.get('message', 'Unknown error')}")
        return

    reports = list_response['data']
    if not reports:
        print("No reports found to audit.")
        return

    print("Available Reports:")
    for r in reports:
        print(
            f"  - ID: {r['id'][:8]}... | Doctor: {r['doctor'][-4:]} | Time: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(float(r['timestamp'])))}")

    target_id_prefix = input("Enter the START of a Report ID to view details: ").strip()
    if not target_id_prefix:
        return

    target_report = next((r for r in reports if r['id'].startswith(target_id_prefix)), None)
    if not target_report:
        print("Report not found.")
        return

    # Fetch details
    detail_response = send_request('audit_report_details', {'report_id': target_report['id']})
    if not detail_response or detail_response['status'] != 'SUCCESS':
        print(f"❌ Failed to fetch details: {detail_response.get('message', 'Unknown error')}")
        return

    report_data = detail_response['data']

    # 1. RSA Decryption of AES Key (Key Transport)
    try:
        encrypted_aes_key = bytes.fromhex(report_data['encrypted_aes_key'])

        aes_key = AUDITOR_RSA_PRIV_KEY.decrypt(
            encrypted_aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    except Exception as e:
        print(f"\n❌ Error decrypting AES key (RSA failure): {e}")
        return

    # 2. AES-256 Decryption of Content (Authenticated Decryption)
    try:
        encrypted_content_with_nonce = bytes.fromhex(report_data['encrypted_content'])
        # Assuming nonce is prepended (12 bytes standard GCM)
        nonce = encrypted_content_with_nonce[:12]
        ciphertext_and_tag = encrypted_content_with_nonce[12:]

        aesgcm = AESGCM(aes_key)
        decrypted_content = aesgcm.decrypt(nonce, ciphertext_and_tag, None).decode('utf-8')

    except Exception as e:
        print(f"\n❌ Error decrypting report content (AES-GCM failure): {e}")
        print("This could be due to a failed authentication tag (tampering).")
        return

    # 3. Display Audit Results
    print(f"\n--- AUDIT RESULT: {target_report['id'][:8]}... ---")
    print(f"Doctor ID: {report_data['doctor_id']}")
    print(f"Timestamp: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(float(report_data['timestamp'])))}")
    print("-" * 30)
    print("DECRYPTED REPORT CONTENT:")
    print(decrypted_content)
    print("-" * 30)
    print(f"Signature (ElGamal): {report_data['signature']}")


# --- MAIN MENU LOGIC ---

def doctor_menu():
    """Interactive menu for the Doctor role."""
    while True:
        print("\n--- Doctor Menu ---")
        if DOCTOR_ID:
            print(f"ID: {DOCTOR_ID} | HE Key: {SERVER_RSA_HE_PUB_KEY[:10]}...")
        else:
            print("Status: Unregistered")

        print("1. Register (Must be first)")
        print("2. Submit Medical Report (Securely)")
        print("3. Log Encrypted Expense (Privacy-Preserving)")
        print("4. Back to Main Menu")

        choice = input("Select an option: ").strip()

        if choice == '1':
            doctor_register()
        elif choice == '2':
            doctor_submit_report()
        elif choice == '3':
            doctor_log_expense()
        elif choice == '4':
            break
        else:
            print("Invalid choice. Please try again.")


def auditor_menu():
    """Interactive menu for the Auditor role."""
    while True:
        print("\n--- Auditor Menu (Admin Access) ---")
        print("1. Privacy-Preserving Search by Department Keyword (Paillier HE)")
        print("2. Privacy-Preserving Summation of Expenses (RSA-HE)")
        print("3. List, Audit, and Decrypt Reports")
        print("4. Back to Main Menu")

        choice = input("Select an option: ").strip()

        if choice == '1':
            auditor_search_doctors()
        elif choice == '2':
            auditor_sum_expenses()
        elif choice == '3':
            auditor_audit_reports()
        elif choice == '4':
            break
        else:
            print("Invalid choice. Please try again.")


def main_menu():
    """Main application menu."""
    print("Welcome to the Privacy-Preserving Medical Records System")
    while True:
        print("\n--- Main Menu ---")
        print("Select Role:")
        print("1. Doctor (Data Submitter)")
        print("2. Auditor (Query/Audit Analyst)")
        print("3. Exit")

        role_choice = input("Select a role: ").strip()

        if role_choice == '1':
            doctor_menu()
        elif role_choice == '2':
            auditor_menu()
        elif role_choice == '3':
            print("Exiting application. Goodbye!")
            break
        else:
            print("Invalid choice. Please try again.")


if __name__ == '__main__':
    main_menu()
