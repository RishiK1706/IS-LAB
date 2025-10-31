import socket
import threading
import json
import time
import os
import uuid
from cryptography.hazmat.primitives.asymmetric import rsa, padding, utils
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


# --- MOCKED CRYPTOGRAPHIC PRIMITIVES (FOR ARCHITECTURAL DEMO) ---
# These functions simulate the behavior of the required advanced schemes
# without actual cryptographic implementation.

def rsa_he_multiply(c1_str, c2_str):
    """Mocks RSA-HE multiplicative property for expense summation: E(a)*E(b) = E(a+b)."""
    # In a real system, this multiplies large integers modulo n^2.
    print("  [CRYPTO: RSA-HE] Performing homomorphic multiplication (simulated summation)...")
    try:
        c1 = int(c1_str)
        c2 = int(c2_str)
        return str(c1 + c2)  # Simple addition mock for demonstration
    except ValueError:
        return "0"


def rsa_he_decrypt(c_str, priv_key_str):
    """Mocks RSA-HE decryption of the final sum."""
    print("  [CRYPTO: RSA-HE] Decrypting final homomorphic sum...")
    return int(c_str)


def paillier_homomorphic_subtract(c1_str, c2_str):
    """Mocks Paillier HE for department search: E(D)*E(Q)^-1 = E(D-Q)."""
    # If D == Q, the result should be E(0).
    print("  [CRYPTO: PAILLIER] Performing homomorphic subtraction (simulated equality check)...")
    try:
        c1 = int(c1_str)
        c2 = int(c2_str)
        # Mocking the E(D-Q) result: 0 if equal, non-zero otherwise
        return "0_CIPHERTEXT" if c1 == c2 else "NON_ZERO_CIPHERTEXT"
    except ValueError:
        return "NON_ZERO_CIPHERTEXT"


def paillier_is_ciphertext_zero(c_str):
    """Mocks checking if the Paillier result is E(0)."""
    return c_str == "0_CIPHERTEXT"


def elgamal_verify(pub_key_str, message, signature_str):
    """Mocks ElGamal signature verification."""
    print(f"  [CRYPTO: ELGAMAL] Verifying signature for message hash: {message[:15]}...")
    # Signature is valid if the hash of the message matches the mocked signature
    # In a real system, this involves complex modular exponentiation
    return hashes.SHA256(message.encode()).hexdigest()[:10] == signature_str


def generate_server_rsa_he_keys():
    """Generates server's master RSA-HE key pair (mocked)."""
    # Key size is arbitrary for mock, representing the large HE modulus
    n = 2048
    print(f"  [CRYPTO: SERVER INIT] Generating {n}-bit RSA-HE Master Keys (MOCKED)...")
    # For a real RSA-HE scheme, the public key is (n, g) and private is (lambda)
    return {
        # Public key for clients to encrypt expenses
        "pub": "SERVER_RSA_HE_PUB",
        # Private key for the server/auditor to decrypt the final sum
        "priv": "SERVER_RSA_HE_PRIV_KEY"
    }


# --- GLOBAL STATE AND CONFIGURATION ---
SERVER_HOST = '127.0.0.1'
SERVER_PORT = 9999
DATA_FILE = 'server_data.json'
STATE_LOCK = threading.Lock()

SERVER_STATE = {
    'doctors': {},  # Doctor ID -> {pub_keys, encrypted_department}
    'reports': [],  # List of reports
    'expenses': [],  # List of expenses
    'server_keys': {}  # Master RSA-HE keys
}


def load_state():
    """Loads state from JSON file or initializes new state."""
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, 'r') as f:
            global SERVER_STATE
            SERVER_STATE = json.load(f)
        print(f"[STATE] Loaded state from {DATA_FILE}")
    else:
        # Generate master keys on first run
        SERVER_STATE['server_keys'] = generate_server_rsa_he_keys()
        print("[STATE] Initialized new server state.")
        save_state()


def save_state():
    """Saves the current state to the JSON file."""
    with open(DATA_FILE, 'w') as f:
        json.dump(SERVER_STATE, f, indent=4)


# --- SERVER ACTIONS: DOCTOR ---

def register_doctor(data):
    """Registers a new doctor and sends the RSA-HE public key."""
    doc_id = str(uuid.uuid4())

    with STATE_LOCK:
        SERVER_STATE['doctors'][doc_id] = {
            'pub_keys': data['pub_keys'],
            # The Paillier ciphertext of the doctor's department keyword
            'encrypted_department': data['encrypted_department']
        }
        save_state()

    print(f"[DOCTOR] Registered new doctor: {doc_id}. Department: {data['department_name']} (Encrypted)")

    return {
        'doctor_id': doc_id,
        'rsa_he_pub_key': SERVER_STATE['server_keys']['pub']
    }


def submit_report(data):
    """Stores a new report after signature verification."""
    doc_id = data['doctor_id']

    with STATE_LOCK:
        doctor_data = SERVER_STATE['doctors'].get(doc_id)
        if not doctor_data:
            return {'status': 'error', 'message': 'Doctor not found.'}

        # 1. ElGamal Signature Verification
        pub_key_str = doctor_data['pub_keys']['elgamal']
        message = f"{doc_id}|{data['timestamp']}|{data['encrypted_content'][:50]}"

        if not elgamal_verify(pub_key_str, message, data['signature']):
            return {'status': 'error', 'message': 'Signature verification failed. Report rejected.'}

        # 2. Store Report
        SERVER_STATE['reports'].append({
            'report_id': str(uuid.uuid4()),
            'doctor_id': doc_id,
            'encrypted_aes_key': data['encrypted_aes_key'],  # RSA-encrypted AES key
            'encrypted_content': data['encrypted_content'],  # AES-GCM content
            'signature': data['signature'],
            'timestamp': data['timestamp']
        })
        save_state()
        print(f"[REPORT] Report received and verified for Doctor {doc_id}.")
        return {'status': 'ok', 'message': 'Report submitted and signature verified.'}


def log_expense(data):
    """Stores a new expense, which is encrypted with RSA-HE."""
    doc_id = data['doctor_id']

    with STATE_LOCK:
        if doc_id not in SERVER_STATE['doctors']:
            return {'status': 'error', 'message': 'Doctor not found.'}

        SERVER_STATE['expenses'].append({
            'expense_id': str(uuid.uuid4()),
            'doctor_id': doc_id,
            # The RSA-HE ciphertext (mocked string)
            'encrypted_amount': data['encrypted_amount'],
            'timestamp': data['timestamp']
        })
        save_state()
        print(f"[EXPENSE] Expense logged (encrypted) for Doctor {doc_id}.")
        return {'status': 'ok', 'message': 'Expense logged securely.'}


# --- SERVER ACTIONS: AUDITOR (PRIVACY-PRESERVING) ---

def audit_list_reports(data):
    """Lists all report metadata."""
    with STATE_LOCK:
        return [{'id': r['report_id'], 'doctor': r['doctor_id'], 'timestamp': r['timestamp']}
                for r in SERVER_STATE['reports']]


def audit_report_details(data):
    """Retrieves a specific report, including the encrypted AES key and content."""
    report_id = data.get('report_id')
    with STATE_LOCK:
        report = next((r for r in SERVER_STATE['reports'] if r['report_id'] == report_id), None)
        if report:
            # Only return encrypted components for the auditor to decrypt client-side
            return {
                'doctor_id': report['doctor_id'],
                'encrypted_aes_key': report['encrypted_aes_key'],
                'encrypted_content': report['encrypted_content'],
                'signature': report['signature'],
                'timestamp': report['timestamp']
            }
        return {'status': 'error', 'message': 'Report not found.'}


def audit_search_doctors(data):
    """Privacy-preserving keyword search using Paillier HE (MOCKED)."""
    # Auditor sends the Paillier-encrypted search keyword, E(Q)
    encrypted_keyword_query = data['encrypted_keyword']
    matching_doctor_ids = []

    with STATE_LOCK:
        for doc_id, doc_data in SERVER_STATE['doctors'].items():
            encrypted_dept = doc_data['encrypted_department']

            # Paillier Homomorphic Operation: Compute E(stored_dept - query)
            encrypted_difference = paillier_homomorphic_subtract(
                encrypted_dept,
                encrypted_keyword_query
            )

            # Check if E(difference) == E(0). If true, the keywords match.
            if paillier_is_ciphertext_zero(encrypted_difference):
                matching_doctor_ids.append(doc_id)

    return {'matching_doctors': matching_doctor_ids}


def audit_sum_expenses(data):
    """Homomorphic summation of expenses using RSA-HE (MOCKED)."""
    target_doc_id = data.get('doctor_id')

    with STATE_LOCK:
        filtered_expenses = [
            exp['encrypted_amount'] for exp in SERVER_STATE['expenses']
            if not target_doc_id or exp['doctor_id'] == target_doc_id
        ]

    if not filtered_expenses:
        return {'status': 'ok', 'total_decrypted_sum': 0, 'message': 'No expenses found.'}

    # 1. Homomorphic Summation
    # Multiply all ciphertexts (mocked as simple string addition)
    total_ciphertext = filtered_expenses[0]
    for i in range(1, len(filtered_expenses)):
        total_ciphertext = rsa_he_multiply(total_ciphertext, filtered_expenses[i])

    # 2. Final Decryption by the Server/Auditor using the master HE private key
    decrypted_sum = rsa_he_decrypt(total_ciphertext, SERVER_STATE['server_keys']['priv'])

    # Aggregated result is available without ever decrypting individual amounts
    return {
        'status': 'ok',
        'total_encrypted_amount': total_ciphertext,
        'total_decrypted_sum': decrypted_sum,
        'message': f'Total sum calculated homomorphically.'
    }


# --- THREADED CONNECTION HANDLER ---

ACTION_MAP = {
    'register': register_doctor,
    'submit_report': submit_report,
    'log_expense': log_expense,
    'audit_sum_expenses': audit_sum_expenses,
    'audit_search_doctors': audit_search_doctors,
    'audit_list_reports': audit_list_reports,
    'audit_report_details': audit_report_details
}


def handle_client(conn, addr):
    """Handles a single client connection in a separate thread."""
    try:
        data = conn.recv(16384).decode('utf-8')
        if not data:
            return

        request = json.loads(data)
        action = request.get('action')

        print(f"\n[REQUEST] Received action '{action}' from {addr}")

        if action in ACTION_MAP:
            response_data = ACTION_MAP[action](request.get('data', {}))
            response = {'status': 'SUCCESS', 'data': response_data}
        else:
            response = {'status': 'ERROR', 'message': f"Unknown action: {action}"}

    except json.JSONDecodeError:
        print(f"[ERROR] Failed to decode JSON from {addr}")
        response = {'status': 'ERROR', 'message': 'Invalid JSON format.'}
    except Exception as e:
        print(f"[ERROR] An unexpected error occurred: {e}")
        response = {'status': 'ERROR', 'message': f'Server Error: {str(e)}'}
    finally:
        conn.sendall(json.dumps(response).encode('utf-8'))
        conn.close()
        print(f"[RESPONSE] Sent response to {addr}. Connection closed.")


def start_server():
    """Initializes and runs the main server loop."""
    load_state()

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((SERVER_HOST, SERVER_PORT))
        s.listen()
        print(f"\n[SERVER] Listening on {SERVER_HOST}:{SERVER_PORT}")

        try:
            while True:
                conn, addr = s.accept()
                thread = threading.Thread(target=handle_client, args=(conn, addr))
                thread.start()
        except KeyboardInterrupt:
            print("\n[SERVER] Shutting down...")
        finally:
            s.close()
            save_state()


if __name__ == '__main__':
    start_server()
