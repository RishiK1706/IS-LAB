#!/usr/bin/env python3
"""
Secure Payment Simulation:
- Rabin encryption (merchant's public key n = p*q; private p,q used to decrypt)
- ElGamal signature (customer signs SHA-512 hash of plaintext)
- Roles: Customer (create/send), Merchant (process), Auditor (view & verify)
- All storage in-memory, console I/O only.
"""

import hashlib, random, time
from datetime import datetime

# -------------------------
# Utilities: number theory
# -------------------------

def is_probable_prime(n, k=10):
    """Miller-Rabin primality test (probabilistic)."""
    if n < 2:
        return False
    small_primes = [2,3,5,7,11,13,17,19,23,29]
    for p in small_primes:
        if n % p == 0:
            return n == p
    # write n-1 = d * 2^s
    s = 0
    d = n - 1
    while d % 2 == 0:
        d //= 2
        s += 1
    for _ in range(k):
        a = random.randrange(2, n-1)
        x = pow(a, d, n)
        if x == 1 or x == n-1:
            continue
        composite = True
        for _r in range(s-1):
            x = pow(x, 2, n)
            if x == n-1:
                composite = False
                break
        if composite:
            return False
    return True

def gen_prime(bits, congruent3mod4=True):
    """Generate a prime of 'bits' bits; if congruent3mod4=True ensure p % 4 == 3."""
    while True:
        p = random.getrandbits(bits) | (1 << bits-1) | 1
        if congruent3mod4:
            # force p % 4 == 3 by setting two low bits appropriately
            p |= 3
        if is_probable_prime(p):
            if not congruent3mod4 or p % 4 == 3:
                return p

def egcd(a, b):
    if b == 0:
        return (1, 0, a)
    x, y, g = egcd(b, a % b)
    return (y, x - (a // b) * y, g)

def modinv(a, m):
    x, y, g = egcd(a, m)
    if g != 1:
        raise ValueError(f"No modular inverse for {a} mod {m}")
    return x % m

# -------------------------
# Rabin cryptosystem
# -------------------------
def rabin_keygen(bits=512):
    # generate p, q congruent to 3 mod 4
    p = gen_prime(bits, congruent3mod4=True)
    q = gen_prime(bits, congruent3mod4=True)
    while p == q:
        q = gen_prime(bits, congruent3mod4=True)
    n = p * q
    return {'p': p, 'q': q, 'n': n}

def rabin_encrypt(message_bytes, n):
    m = int.from_bytes(message_bytes, 'big')
    if m >= n:
        raise ValueError("Message too long for current Rabin modulus n. Shorten message or use larger keys.")
    c = pow(m, 2, n)
    return c

def _sqrt_mod_p(c, p):
    # p ≡ 3 (mod 4): sqrt = c^{(p+1)/4} mod p
    r = pow(c % p, (p + 1) // 4, p)
    return r

def crt_combine(a1, n1, a2, n2):
    # combine solutions via CRT: find x ≡ a1 (mod n1), x ≡ a2 (mod n2)
    m1_inv = modinv(n1, n2)
    t = ((a2 - a1) * m1_inv) % n2
    x = a1 + n1 * t
    return x

def rabin_decrypt_all(c, p, q):
    # returns four roots (integers) of x^2 = c (mod n)
    r_p = _sqrt_mod_p(c, p)
    r_q = _sqrt_mod_p(c, q)
    # four combinations: ±r_p mod p; ±r_q mod q
    n = p * q
    roots = []
    for sp in (r_p, (-r_p) % p):
        for sq in (r_q, (-r_q) % q):
            x = crt_combine(sp, p, sq, q)
            roots.append(x % n)
    # unique
    roots = list(dict.fromkeys(roots))
    return roots

# -------------------------
# ElGamal signature (basic)
# -------------------------
def elgamal_keygen(bits=512):
    # generate a prime p_g and a generator g
    p = gen_prime(bits, congruent3mod4=False)
    # find small generator g by trial
    for g in range(2, 1000):
        # check g is a generator (naive test: pow(g, (p-1)//q, p) != 1 for prime q dividing p-1)
        # Factor small primes of p-1 (not full factorization). We'll do basic test by ensuring g^(p-1) ≡ 1 and g^1 != 1
        if pow(g, p-1, p) != 1:
            continue
        if pow(g, 1, p) == 1:
            continue
        # accepted
        x = random.randrange(2, p-2)
        y = pow(g, x, p)
        return {'p': p, 'g': g, 'x': x, 'y': y}
    # fallback (shouldn't happen)
    x = random.randrange(2, p-2)
    g = 2
    y = pow(g, x, p)
    return {'p': p, 'g': g, 'x': x, 'y': y}

def elgamal_sign(hash_bytes, priv):
    """Sign a message hash (bytes) using ElGamal.
    priv: dict with p,g,x
    returns (r,s)"""
    p = priv['p']; g = priv['g']; x = priv['x']
    H = int.from_bytes(hash_bytes, 'big') % p  # reduce mod p
    while True:
        k = random.randrange(2, p-2)
        if egcd(k, p-1)[2] == 1:
            break
    r = pow(g, k, p)
    k_inv = modinv(k, p-1)
    s = (k_inv * (H - x * r)) % (p - 1)
    return (r, s)

def elgamal_verify(hash_bytes, signature, pub):
    p = pub['p']; g = pub['g']; y = pub['y']
    H = int.from_bytes(hash_bytes, 'big') % p
    r, s = signature
    if not (1 <= r <= p-1):
        return False
    left = pow(g, H, p)
    right = (pow(y, r, p) * pow(r, s, p)) % p
    return left == right

# -------------------------
# Helpers: hashing, encoding
# -------------------------
def sha512_bytes(data_bytes):
    return hashlib.sha512(data_bytes).digest()

def bytes_from_int(x):
    # Avoid zero-length conversion. Determine minimal length.
    if x == 0:
        return b'\x00'
    length = (x.bit_length() + 7) // 8
    return x.to_bytes(length, 'big')

# -------------------------
# Transaction store and roles
# -------------------------
class TransactionStore:
    def __init__(self):
        self.transactions = []
        self._next_id = 1
    def add(self, record):
        record['id'] = self._next_id
        self._next_id += 1
        self.transactions.append(record)
    def get_pending(self):
        return [t for t in self.transactions if t['status'] == 'pending']
    def get_processed(self):
        return [t for t in self.transactions if t['status'] == 'processed' or t['status']=='failed']
    def find(self, txid):
        for t in self.transactions:
            if t['id'] == txid:
                return t
        return None

# -------------------------
# Setup: generate keys for merchant (Rabin) and customer (ElGamal)
# -------------------------
print("Setting up keys (this may take a few seconds)...")
# Merchant's Rabin keys
RABIN_BITS = 512  # decent for demonstration; increase for real security
rabin_keys = rabin_keygen(bits=RABIN_BITS)
merchant_rabin_pub_n = rabin_keys['n']
merchant_rabin_priv = {'p': rabin_keys['p'], 'q': rabin_keys['q']}

# Customer's ElGamal keys
ELGAMAL_BITS = 512
elgamal = elgamal_keygen(bits=ELGAMAL_BITS)
customer_elgamal_priv = {'p': elgamal['p'], 'g': elgamal['g'], 'x': elgamal['x']}
customer_elgamal_pub = {'p': elgamal['p'], 'g': elgamal['g'], 'y': elgamal['y']}

store = TransactionStore()
print("Setup complete.")
print()
print("Merchant Rabin public modulus n (kept public):", merchant_rabin_pub_n)
print("Customer ElGamal public key (p,g,y):")
print(" p (prime) length:", customer_elgamal_pub['p'].bit_length(), "bits")
print(" g:", customer_elgamal_pub['g'])
print(" y:", customer_elgamal_pub['y'])
print()
time.sleep(0.5)

# -------------------------
# Interactive role actions
# -------------------------
def customer_create_and_send():
    print("\n-- Customer: Create and Send Transaction --")
    print("Enter payment details plaintext (example: 'Send 55000 to Bob using Mastercard 3048...'):")
    plaintext = input("> ").strip().encode('utf-8')
    if len(plaintext) == 0:
        print("Empty message — cancelled.")
        return
    # compute SHA-512 hash of plaintext
    hash_bytes = sha512_bytes(plaintext)
    hash_hex = hash_bytes.hex()
    # sign the hash with ElGamal
    signature = elgamal_sign(hash_bytes, customer_elgamal_priv)
    # encrypt plaintext with Rabin using merchant's public n
    try:
        ciphertext = rabin_encrypt(plaintext, merchant_rabin_pub_n)
    except ValueError as ve:
        print("Error encrypting: ", ve)
        print("Try a shorter message.")
        return
    record = {
        'role_from': 'customer',
        'timestamp_sent': datetime.now().isoformat(),
        'ciphertext': ciphertext,
        'hash_hex': hash_hex,            # transmitted hash (in hex)
        'signature': signature,          # (r,s)
        'elgamal_pub': customer_elgamal_pub.copy(),  # include for verification by merchant/auditor
        'status': 'pending',
        'processed_info': None
    }
    store.add(record)
    print(f"Transaction created and recorded with id {record['id']}. (ciphertext stored, hash & signature included)")
    print("Confidentiality maintained: stored ciphertext only; only merchant can decrypt.")


def merchant_process_all():
    pending = store.get_pending()
    if not pending:
        print("\n-- Merchant: No pending transactions --")
        return
    print(f"\n-- Merchant: Processing {len(pending)} pending transaction(s) --")
    for t in pending:
        print("\nProcessing tx id:", t['id'])
        c = t['ciphertext']
        received_hash_hex = t['hash_hex']
        signature = t['signature']
        elg_pub = t['elgamal_pub']
        possible_roots = rabin_decrypt_all(c, merchant_rabin_priv['p'], merchant_rabin_priv['q'])
        found_plain = None
        computed_hash_hex = None
        for root in possible_roots:
            # convert candidate int -> bytes -> try to compute sha512
            candidate_bytes = bytes_from_int(root)
            # attempt to decode as utf-8 — but don't require success; we only need hash equality.
            h = sha512_bytes(candidate_bytes).hex()
            if h == received_hash_hex:
                found_plain = candidate_bytes
                computed_hash_hex = h
                break
        if found_plain is None:
            # none matched: mark failure
            t['status'] = 'failed'
            t['processed_info'] = {
                'processed_at': datetime.now().isoformat(),
                'result': 'decryption_failed_or_hash_mismatch',
                'computed_hash_hex': None,
                'plaintext_revealed': None,
                'signature_verified': False
            }
            print("Failed: none of the Rabin roots produce a hash matching the transmitted hash.")
            continue
        # If matched, verify signature
        sig_valid = elgamal_verify(bytes.fromhex(computed_hash_hex), signature, elg_pub)
        t['status'] = 'processed'
        t['processed_info'] = {
            'processed_at': datetime.now().isoformat(),
            'result': 'ok' if sig_valid else 'hash_ok_but_signature_invalid',
            'computed_hash_hex': computed_hash_hex,
            # store plaintext here since merchant is allowed to see it (confidential). For auditor, we won't show plaintext.
            'plaintext_revealed': found_plain.decode('utf-8', errors='replace'),
            'signature_verified': sig_valid
        }
        print("Decryption succeeded. Computed hash matches transmitted hash.")
        print("Signature verification:", "VALID" if sig_valid else "INVALID")
        if not sig_valid:
            print("Warning: signature invalid — possible tampering or incorrect key.")
        else:
            print("Transaction processed and marked as processed.")

def auditor_view_and_verify():
    processed = store.get_processed()
    if not processed:
        print("\n-- Auditor: No processed transactions to view --")
        return
    print(f"\n-- Auditor: Viewing {len(processed)} processed/failed transactions --")
    for t in processed:
        print("\nTransaction id:", t['id'])
        print("Status:", t['status'])
        print("Timestamp sent:", t['timestamp_sent'])
        pi = t['processed_info'] or {}
        # Auditor sees hashes and signature verification result, but NOT plaintext_revealed
        print("Received hash (from customer):", t['hash_hex'][:64], "..." if len(t['hash_hex'])>64 else "")
        ch = pi.get('computed_hash_hex')
        print("Computed hash (by merchant):", (ch[:64] + "...") if ch and len(ch)>64 else (ch or "N/A"))
        print("Signature verified by merchant:", pi.get('signature_verified'))
        # Auditor can independently verify using customer's public key
        elg_pub = t['elgamal_pub']
        signature = t['signature']
        try:
            # For verification auditor uses the received hash (hex) -> bytes
            h_bytes = bytes.fromhex(t['hash_hex'])
            auditor_check = elgamal_verify(h_bytes, signature, elg_pub)
        except Exception as e:
            auditor_check = False
        print("Auditor's independent signature verification:", auditor_check)
        print("Processed result note:", pi.get('result'))

def show_history():
    print("\n=== Transaction History (summary) ===")
    for t in store.transactions:
        print(f"ID {t['id']}: status={t['status']}, sent={t['timestamp_sent']}, hash_prefix={t['hash_hex'][:12]}...")
    print("=== end ===")

# -------------------------
# Main loop
# -------------------------
def main_loop():
    MENU = """
Select role:
1) Customer (create and send transaction)
2) Merchant (process pending transactions)
3) Auditor (view processed tx hashes and verify signatures)
4) Show transaction summary
5) Exit
Choose: """
    while True:
        choice = input(MENU).strip()
        if choice == '1':
            customer_create_and_send()
        elif choice == '2':
            merchant_process_all()
        elif choice == '3':
            auditor_view_and_verify()
        elif choice == '4':
            show_history()
        elif choice == '5':
            print("Exiting. Goodbye.")
            break
        else:
            print("Invalid choice.")

if __name__ == '__main__':
    try:
        main_loop()
    except KeyboardInterrupt:
        print("\nInterrupted. Exiting.")

