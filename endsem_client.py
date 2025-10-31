# client.py

import socket
import json
import os
from datetime import datetime
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


# --- CRYPTOGRAPHIC UTILITIES ---

def generate_key_pair(key_size=2048):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    public_key = private_key.public_key()
    return private_key, public_key


def rsa_encrypt(public_key, data):
    ciphertext = public_key.encrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext.hex()


def aes_encrypt(key, data):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(data.encode('utf-8')) + encryptor.finalize()
    return ciphertext.hex(), iv.hex()


def elgamal_sign(private_key, message):
    signature = private_key.sign(
        message.encode('utf-8'),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature.hex()


# --- RSA Homomorphic Encryption (Exponent Trick) Implementation ---

def rsa_homomorphic_encrypt(public_key, amount_int):
    amount_bytes = str(amount_int).encode()
    ciphertext = public_key.encrypt(
        amount_bytes,
        padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext.hex()


def rsa_homomorphic_multiplication(encrypted_amounts_hex_list, public_key):
    """Performs homomorphic summation by multiplying ciphertexts mod N."""
    if not encrypted_amounts_hex_list:
        return None

    n = public_key.public_numbers().n

    # Crucial: Determine the expected length for zfill
    expected_hex_length = len(encrypted_amounts_hex_list[0])

    c_sum = 1

    for c_hex in encrypted_amounts_hex_list:
        c_i = int(c_hex, 16)
        c_sum = (c_sum * c_i) % n

    # Convert the resulting integer to a padded hex string
    hex_sum = hex(c_sum)[2:].zfill(expected_hex_length)

    return hex_sum


# --- CLIENT STATE AND UTILITIES ---

HOST = '127.0.0.1'
PORT = 65432


class Client:
    def __init__(self, role):
        self.role = role
        self.doctor_id = None
        self.rsa_priv_key = None
        self.rsa_pub_key = None
        self.elgamal_priv_key = None
        self.elgamal_pub_key = None
        self.server_rsa_pub_key = None
        self.rsa_homomorphic_pub_key = None

    def connect(self):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.connect((HOST, PORT))

    def send_request(self, data):
        self.socket.sendall(json.dumps(data).encode('utf-8'))
        response_data = self.socket.recv(4096).decode('utf-8')
        return json.loads(response_data)

    def load_server_keys(self):
        try:
            with open('server_rsa_pub.pem', 'rb') as f:
                self.server_rsa_pub_key = serialization.load_pem_public_key(f.read(), backend=default_backend())

            response = self.send_request({'action': 'auditor_get_rsa_homomorphic_pubkey'})
            if response['status'] == 'OK':
                self.rsa_homomorphic_pub_key = serialization.load_pem_public_key(response['key_pem'].encode('utf-8'),
                                                                                 backend=default_backend())
            else:
                print("Error loading RSA Homomorphic Key.")

        except FileNotFoundError:
            print("Server RSA public key file not found. Ensure server is running.")
            return False
        except Exception as e:
            print(f"Error during server key loading: {e}")
            return False

        return True

    def run(self):
        self.connect()
        print(f"Connected to server as {self.role.upper()}.")

        if not self.load_server_keys():
            self.socket.close()
            return

        if self.role == 'doctor':
            self.doctor_menu()
        elif self.role == 'auditor':
            self.auditor_menu()

        self.socket.close()

    # --- DOCTOR MENU IMPLEMENTATION ---

    def doctor_menu(self):
        while True:
            print("\n--- Doctor Menu ---")
            print("1. Register")
            print("2. Submit Medical Report")
            print("3. Log Expense")
            print("4. Exit")
            choice = input("Enter choice: ")

            if choice == '1':
                self.handle_registration()
            elif choice == '2':
                self.handle_report_submission()
            elif choice == '3':
                self.handle_expense_logging()
            elif choice == '4':
                break
            else:
                print("Invalid choice.")

    def handle_registration(self):
        if self.doctor_id:
            print("Already registered.")
            return

        doc_id = input("Enter Doctor ID: ")
        department = input("Enter Department (e.g., Cardiology): ")

        self.rsa_priv_key, self.rsa_pub_key = generate_key_pair()
        self.elgamal_priv_key, self.elgamal_pub_key = generate_key_pair()

        rsa_pub_pem = self.rsa_pub_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()

        elgamal_pub_pem = self.elgamal_pub_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()

        request = {
            'action': 'register',
            'doctor_id': doc_id,
            'department': department,
            'rsa_pub_key_pem': rsa_pub_pem,
            'elgamal_pub_key_pem': elgamal_pub_pem
        }
        response = self.send_request(request)
        print(f"Server Response: {response['message']}")

        if response['status'] == 'OK':
            self.doctor_id = doc_id
            print(f"Doctor {doc_id} registered.")

    def handle_report_submission(self):
        if not self.doctor_id:
            print("Please register first.")
            return

        patient_data = input("Enter patient data/report content: ")

        aes_key = os.urandom(32)
        encrypted_content_hex, iv_hex = aes_encrypt(aes_key, patient_data)
        encrypted_aes_key_hex = rsa_encrypt(self.server_rsa_pub_key, aes_key)

        timestamp = datetime.now().isoformat()
        message_to_sign = f"{self.doctor_id}|{timestamp}|{encrypted_aes_key_hex}|{iv_hex}|{encrypted_content_hex}"
        signature_hex = elgamal_sign(self.elgamal_priv_key, message_to_sign)

        request = {
            'action': 'submit_report',
            'doctor_id': self.doctor_id,
            'timestamp': timestamp,
            'encrypted_aes_key': encrypted_aes_key_hex,
            'aes_iv': iv_hex,
            'encrypted_report_content': encrypted_content_hex,
            'signature': signature_hex
        }
        response = self.send_request(request)
        print(f"Server Response: {response['message']}")

    def handle_expense_logging(self):
        if not self.doctor_id:
            print("Please register first.")
            return

        try:
            amount = int(input("Enter expense amount (integer): "))
            if amount <= 0:
                raise ValueError
        except ValueError:
            print("Invalid amount. Must be a positive integer.")
            return

        encrypted_amount_hex = rsa_homomorphic_encrypt(self.rsa_homomorphic_pub_key, amount)

        request = {
            'action': 'log_expense',
            'doctor_id': self.doctor_id,
            'timestamp': datetime.now().isoformat(),
            'encrypted_amount': encrypted_amount_hex
        }
        response = self.send_request(request)
        print(f"Server Response: {response['message']}")

    # --- AUDITOR MENU IMPLEMENTATION ---

    def auditor_menu(self):
        while True:
            print("\n--- Auditor Menu ---")
            print("1. Search Doctors by Department (Privacy-Preserving)")
            print("2. Sum Encrypted Expenses")
            print("3. List and Audit Reports (Verify Signatures/Timestamps)")
            print("4. Exit")
            choice = input("Enter choice: ")

            if choice == '1':
                self.handle_auditor_search()
            elif choice == '2':
                self.handle_auditor_sum_expenses()
            elif choice == '3':
                self.handle_auditor_list_reports()
            elif choice == '4':
                break
            else:
                print("Invalid choice.")

    def handle_auditor_search(self):
        keyword = input("Enter Department Keyword to search: ")

        request = {
            'action': 'auditor_search',
            'keyword': keyword
        }
        response = self.send_request(request)

        if response['status'] == 'OK':
            print("\n--- Matching Doctors ---")
            if response['matches']:
                for doctor in response['matches']:
                    print(f"ID: {doctor['id']}, Dept: {doctor['department_keyword']}")
            else:
                print("No doctors matched the search keyword.")
        else:
            print(f"Error: {response['message']}")

    def handle_auditor_sum_expenses(self):
        sum_type = input("Sum (A)ll expenses or (P)er-doctor? (A/P): ").upper()

        target_id = None
        if sum_type == 'P':
            target_id = input("Enter Doctor ID to sum: ")

        # 1. Request list of encrypted expenses
        request = {
            'action': 'auditor_sum_expenses',
            'doctor_id': target_id
        }
        response = self.send_request(request)

        if response['status'] == 'OK':
            encrypted_amounts = response['encrypted_amounts']
            if not encrypted_amounts:
                print(f"No expenses found for {response['doctor_id']}.")
                return

            # 2. Perform Homomorphic Multiplication (Summation)
            C_sum = rsa_homomorphic_multiplication(encrypted_amounts, self.rsa_homomorphic_pub_key)

            # 3. Display Encrypted Result only (Privacy Preserving)
            print(f"\nTotal Expenses (Target: {response['doctor_id']})")
            print("--------------------------------------------------")
            print(f"**Encrypted Sum (C_sum):** {C_sum[:40]}... (Length: {len(C_sum)})")
            print("**Decryption is withheld to maintain expense privacy.**")
            print("--------------------------------------------------")

        else:
            print(f"Error: {response['message']}")

    def handle_auditor_list_reports(self):
        request = {
            'action': 'auditor_list_reports'
        }
        response = self.send_request(request)

        if response['status'] == 'OK':
            print("\n--- Audited Reports Summary ---")
            if not response['reports']:
                print("No records found to audit.")
                return

            print("--------------------------------------------------------------------")
            print(f"{'Doctor ID':<10} | {'Timestamp':<28} | {'Signature Status':<20}")
            print("--------------------------------------------------------------------")
            for report in response['reports']:
                sig_status = "OK ✅" if report['signature_ok'] else "FAILED ❌"
                print(f"{report['doctor_id']:<10} | {report['timestamp']:<28} | {sig_status:<20}")
            print("--------------------------------------------------------------------")
        else:
            print(f"Error: {response['message']}")


# --- MAIN EXECUTION ---

if __name__ == '__main__':
    while True:
        print("\n--- User Role Selection ---")
        print("1. Doctor")
        print("2. Auditor")
        print("3. Exit")
        role_choice = input("Select role: ")

        if role_choice == '1':
            client = Client('doctor')
            client.run()
        elif role_choice == '2':
            client = Client('auditor')
            client.run()
        elif role_choice == '3':
            print("Exiting client.")
            break
        else:
            print("Invalid choice.")
