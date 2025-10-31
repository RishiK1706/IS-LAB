# server.py

import socket
import threading
import json
import os
import hashlib
from datetime import datetime
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend


# --- SIMPLIFIED CRYPTOGRAPHIC PLACEHOLDERS (NOT PRODUCTION-READY) ---

# Paillier Placeholder for Homomorphic Search
class Paillier:
    def __init__(self):
        pass

    def encrypt(self, keyword):
        return hashlib.sha256(keyword.encode()).hexdigest()

    def compare_encrypted(self, c1, c2):
        return c1 == c2


# RSA Homomorphic Placeholder for Expense Summation (Exponent Trick)
class RSAHomomorphic:
    def __init__(self, key_size=2048):
        # We keep the key pair to distribute the public key for encryption
        self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
        self.public_key = self.private_key.public_key()

    def get_public_key_pem(self):
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )


# ElGamal Placeholder for Signature (using RSA for simplicity)
class ElGamalSignature:
    @staticmethod
    def verify(public_key_pem, message, signature):
        try:
            public_key = serialization.load_pem_public_key(public_key_pem.encode('utf-8'), backend=default_backend())
            public_key.verify(
                bytes.fromhex(signature),
                message.encode('utf-8'),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except Exception:
            return False


# --- SERVER STATE AND UTILITIES ---

DATA_FILE = 'server_state.json'
LOCK = threading.Lock()
PAILLIER = Paillier()
RSA_HOMOMORPHIC = RSAHomomorphic()


def load_state():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, 'r') as f:
            return json.load(f)
    return {'doctors': {}, 'reports': [], 'expenses': {}}


def save_state(state):
    with open(DATA_FILE, 'w') as f:
        json.dump(state, f, indent=4)


def send_response(conn, data):
    try:
        conn.sendall(json.dumps(data).encode('utf-8'))
    except BrokenPipeError:
        print("Client disconnected unexpectedly.")


def handle_doctor_registration(data, state):
    doc_id = data['doctor_id']
    with LOCK:
        if doc_id in state['doctors']:
            return {'status': 'ERROR', 'message': 'Doctor ID already exists.'}

        state['doctors'][doc_id] = {
            'rsa_pub_key_pem': data['rsa_pub_key_pem'],
            'elgamal_pub_key_pem': data['elgamal_pub_key_pem'],
            'encrypted_department': PAILLIER.encrypt(data['department']),
            'department_keyword': data['department']
        }
        state['expenses'][doc_id] = []
        save_state(state)
        return {'status': 'OK', 'message': 'Registration successful.'}


def handle_report_submission(data, state):
    doc_id = data['doctor_id']
    with LOCK:
        if doc_id not in state['doctors']:
            return {'status': 'ERROR', 'message': 'Doctor not registered.'}

        report_data = f"{doc_id}|{data['timestamp']}|{data['encrypted_aes_key']}|{data['aes_iv']}|{data['encrypted_report_content']}"
        pub_key_pem = state['doctors'][doc_id]['elgamal_pub_key_pem']

        if not ElGamalSignature.verify(pub_key_pem, report_data, data['signature']):
            print(f"Signature failed for doctor {doc_id} report at {data['timestamp']}")
            return {'status': 'ERROR', 'message': 'Signature verification failed.'}

        report = {
            'doctor_id': doc_id,
            'timestamp': data['timestamp'],
            'encrypted_aes_key': data['encrypted_aes_key'],
            'aes_iv': data['aes_iv'],
            'encrypted_report_content': data['encrypted_report_content'],
            'signature': data['signature']
        }
        state['reports'].append(report)
        save_state(state)
        return {'status': 'OK', 'message': 'Report submitted securely.'}


def handle_expense_logging(data, state):
    doc_id = data['doctor_id']
    with LOCK:
        if doc_id not in state['doctors']:
            return {'status': 'ERROR', 'message': 'Doctor not registered.'}

        encrypted_amount = data['encrypted_amount']
        timestamp = data['timestamp']

        state['expenses'][doc_id].append({
            'timestamp': timestamp,
            'encrypted_amount': encrypted_amount
        })
        save_state(state)
        return {'status': 'OK', 'message': 'Expense logged securely and encrypted.'}


# --- AUDITOR CAPABILITIES ---

def handle_auditor_search(data, state):
    search_keyword = data['keyword']
    encrypted_keyword = PAILLIER.encrypt(search_keyword)
    matching_doctors = []

    with LOCK:
        for doc_id, doc_data in state['doctors'].items():
            if PAILLIER.compare_encrypted(doc_data['encrypted_department'], encrypted_keyword):
                matching_doctors.append({
                    'id': doc_id,
                    'department_keyword': doc_data['department_keyword']
                })

        return {'status': 'OK', 'matches': matching_doctors}


def handle_auditor_sum_expenses(data, state):
    # Returns all encrypted amounts for homomorphic summation on the client side.
    target_id = data.get('doctor_id')

    with LOCK:
        if target_id and target_id in state['expenses']:
            encrypted_amounts = [e['encrypted_amount'] for e in state['expenses'][target_id]]
            return {'status': 'OK', 'doctor_id': target_id, 'encrypted_amounts': encrypted_amounts}
        elif not target_id:
            all_expenses = []
            for doc_id, expenses in state['expenses'].items():
                all_expenses.extend([e['encrypted_amount'] for e in expenses])
            return {'status': 'OK', 'doctor_id': 'ALL', 'encrypted_amounts': all_expenses}
        else:
            return {'status': 'ERROR', 'message': 'Doctor not found.'}


def handle_auditor_get_rsa_homomorphic_pubkey(state):
    # Sends the public key needed by the client for encryption and multiplication.
    return {'status': 'OK', 'key_pem': RSA_HOMOMORPHIC.get_public_key_pem().decode()}


def handle_auditor_list_reports(state):
    with LOCK:
        reports_summary = []
        for r in state['reports']:
            message_to_verify = f"{r['doctor_id']}|{r['timestamp']}|{r['encrypted_aes_key']}|{r['aes_iv']}|{r['encrypted_report_content']}"

            if r['doctor_id'] in state['doctors']:
                pub_key_pem = state['doctors'][r['doctor_id']]['elgamal_pub_key_pem']
                signature_ok = ElGamalSignature.verify(pub_key_pem, message_to_verify, r['signature'])
            else:
                signature_ok = False

            reports_summary.append({
                'doctor_id': r['doctor_id'],
                'timestamp': r['timestamp'],
                'signature_ok': signature_ok
            })

        return {'status': 'OK', 'reports': reports_summary}


# --- MAIN SERVER LOGIC ---

def handle_client(conn, addr, state):
    print(f"Connection from {addr}")
    while True:
        try:
            data_recv = conn.recv(4096).decode('utf-8')
            if not data_recv:
                break

            data = json.loads(data_recv)
            action = data.get('action')
            response = {}

            if action == 'register':
                response = handle_doctor_registration(data, state)
            elif action == 'submit_report':
                response = handle_report_submission(data, state)
            elif action == 'log_expense':
                response = handle_expense_logging(data, state)
            elif action == 'auditor_search':
                response = handle_auditor_search(data, state)
            elif action == 'auditor_sum_expenses':
                response = handle_auditor_sum_expenses(data, state)
            elif action == 'auditor_get_rsa_homomorphic_pubkey':
                response = handle_auditor_get_rsa_homomorphic_pubkey(state)
            elif action == 'auditor_list_reports':
                response = handle_auditor_list_reports(state)
            # The 'auditor_decrypt_sum' action is now REMOVED
            else:
                response = {'status': 'ERROR', 'message': 'Unknown action'}

            send_response(conn, response)

        except json.JSONDecodeError:
            print(f"JSON decode error from {addr}")
            send_response(conn, {'status': 'ERROR', 'message': 'Invalid JSON format.'})
            break
        except Exception as e:
            print(f"An error occurred with {addr}: {e}")
            break

    print(f"Connection closed for {addr}")
    conn.close()


def start_server():
    HOST = '127.0.0.1'
    PORT = 65432
    state = load_state()

    global SERVER_RSA_KEY
    SERVER_RSA_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    global SERVER_RSA_PUB_KEY_PEM
    SERVER_RSA_PUB_KEY_PEM = SERVER_RSA_KEY.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()

    with open('server_rsa_pub.pem', 'w') as f:
        f.write(SERVER_RSA_PUB_KEY_PEM)

    print(f"Server RSA Public Key saved to server_rsa_pub.pem for doctor use.")
    print(f"Server RSA Homomorphic Public Key is: {RSA_HOMOMORPHIC.get_public_key_pem().decode()[:50]}...")

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((HOST, PORT))
    server_socket.listen()
    print(f"Server listening on {HOST}:{PORT}")
    print("-----------------------------------")

    while True:
        try:
            conn, addr = server_socket.accept()
            thread = threading.Thread(target=handle_client, args=(conn, addr, state))
            thread.start()
            print(f"Active connections: {threading.active_count() - 1}")
        except KeyboardInterrupt:
            print("\nShutting down server...")
            server_socket.close()
            break
        except Exception as e:
            print(f"Server error: {e}")


if __name__ == '__main__':
    start_server()
