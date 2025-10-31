#!/usr/bin/env python3
"""
Secure Payment Simulation:
- ElGamal encryption (merchant holds decryption key)
- SHA-512 hashing
- ElGamal signature (customer signs hash)
- Roles: Customer (create/send), Merchant (process), Auditor (verify)
"""

import hashlib, random, time
from datetime import datetime

# -------------------------
# Utilities
# -------------------------

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

def is_probable_prime(n, k=10):
    if n < 2:
        return False
    small_primes = [2,3,5,7,11,13,17,19,23,29]
    for p in small_primes:
        if n % p == 0:
            return n == p
    s, d = 0, n-1
    while d % 2 == 0:
        s += 1
        d //= 2
    for _ in range(k):
        a = random.randrange(2, n-1)
        x = pow(a, d, n)
        if x in (1, n-1):
            continue
        for __ in range(s-1):
            x = pow(x, 2, n)
            if x == n-1: break
        else:
            return False
    return True

def gen_prime(bits):
    while True:
        p = random.getrandbits(bits) | (1 << (bits-1)) | 1
        if is_probable_prime(p): return p

# -------------------------
# ElGamal encryption
# -------------------------
def elgamal_keygen(bits=512):
    p = gen_prime(bits)
    g = 2
    x = random.randrange(2, p-2)
    y = pow(g, x, p)
    return {'p': p, 'g': g, 'x': x, 'y': y}

def elgamal_encrypt(m_int, pub):
    p, g, y = pub['p'], pub['g'], pub['y']
    k = random.randrange(2, p-2)
    a = pow(g, k, p)
    b = (pow(y, k, p) * m_int) % p
    return (a, b)

def elgamal_decrypt(cipher, priv):
    p, x = priv['p'], priv['x']
    a, b = cipher
    s = pow(a, x, p)
    s_inv = modinv(s, p)
    m = (b * s_inv) % p
    return m

# -------------------------
# ElGamal signature
# -------------------------
def elgamal_sign(hash_bytes, priv):
    p, g, x = priv['p'], priv['g'], priv['x']
    H = int.from_bytes(hash_bytes, 'big') % p
    while True:
        k = random.randrange(2, p-2)
        if egcd(k, p-1)[2] == 1: break
    r = pow(g, k, p)
    k_inv = modinv(k, p-1)
    s = (k_inv * (H - x * r)) % (p-1)
    return (r, s)

def elgamal_verify(hash_bytes, signature, pub):
    p, g, y = pub['p'], pub['g'], pub['y']
    H = int.from_bytes(hash_bytes, 'big') % p
    r, s = signature
    if not (1 <= r <= p-1): return False
    left = pow(g, H, p)
    right = (pow(y, r, p) * pow(r, s, p)) % p
    return left == right

# -------------------------
# Helpers
# -------------------------
def sha512_bytes(data_bytes):
    return hashlib.sha512(data_bytes).digest()

def int_from_bytes(b):
    return int.from_bytes(b, 'big')

def bytes_from_int(x):
    length = (x.bit_length() + 7) // 8 or 1
    return x.to_bytes(length, 'big')

# -------------------------
# Transaction Store
# -------------------------
class TransactionStore:
    def __init__(self): self.transactions = []; self._id=1
    def add(self, rec): rec['id']=self._id; self._id+=1; self.transactions.append(rec)
    def get_pending(self): return [t for t in self.transactions if t['status']=='pending']
    def get_processed(self): return [t for t in self.transactions if t['status']!='pending']

# -------------------------
# Setup
# -------------------------
print("Setting up keys...")
MERCHANT_BITS = 512
CUSTOMER_BITS = 512

merchant_keys = elgamal_keygen(MERCHANT_BITS)
merchant_pub = {'p': merchant_keys['p'], 'g': merchant_keys['g'], 'y': merchant_keys['y']}
merchant_priv = {'p': merchant_keys['p'], 'g': merchant_keys['g'], 'x': merchant_keys['x']}

customer_keys = elgamal_keygen(CUSTOMER_BITS)
customer_pub = {'p': customer_keys['p'], 'g': customer_keys['g'], 'y': customer_keys['y']}
customer_priv = {'p': customer_keys['p'], 'g': customer_keys['g'], 'x': customer_keys['x']}

store = TransactionStore()
print("Setup done.")

# -------------------------
# Roles
# -------------------------
def customer_create():
    print("\n-- Customer Create --")
    msg = input("Enter payment details: ").encode()
    H = sha512_bytes(msg)
    sig = elgamal_sign(H, customer_priv)
    m_int = int_from_bytes(msg)
    if m_int >= merchant_pub['p']:
        print("Message too long for modulus, use shorter text!")
        return
    cipher = elgamal_encrypt(m_int, merchant_pub)
    rec = {
        'cipher': cipher, 'hash_hex': H.hex(),
        'signature': sig, 'cust_pub': customer_pub,
        'status':'pending', 'timestamp': datetime.now().isoformat()
    }
    store.add(rec)
    print("Transaction created.")

def merchant_process():
    pend = store.get_pending()
    if not pend:
        print("No pending tx."); return
    for t in pend:
        print("\nProcessing tx id",t['id'])
        a,b = t['cipher']
        m_int = elgamal_decrypt((a,b), merchant_priv)
        m_bytes = bytes_from_int(m_int)
        H2 = sha512_bytes(m_bytes).hex()
        ok_hash = (H2 == t['hash_hex'])
        sig_ok = elgamal_verify(bytes.fromhex(t['hash_hex']), t['signature'], t['cust_pub'])
        t['status'] = 'processed'
        t['processed'] = {
            'ok_hash': ok_hash, 'sig_ok': sig_ok,
            'plaintext': m_bytes.decode(errors='replace'),
            'time': datetime.now().isoformat()
        }
        print("Decrypted:", t['processed']['plaintext'])
        print("Hash match:", ok_hash, " Signature:", sig_ok)

def auditor_view():
    pro = store.get_processed()
    if not pro:
        print("No processed tx."); return
    for t in pro:
        print("\nTx id",t['id'],"status",t['status'])
        print("Received hash:",t['hash_hex'][:32],"...")
        ok = elgamal_verify(bytes.fromhex(t['hash_hex']), t['signature'], t['cust_pub'])
        print("Auditor signature check:",ok)

def show_summary():
    for t in store.transactions:
        print(f"ID {t['id']} status={t['status']} hash={t['hash_hex'][:12]}...")

# -------------------------
# Main Loop
# -------------------------
def main():
    MENU="""
1) Customer create tx
2) Merchant process
3) Auditor view
4) Summary
5) Exit
Choose: """
    while True:
        ch=input(MENU).strip()
        if ch=='1': customer_create()
        elif ch=='2': merchant_process()
        elif ch=='3': auditor_view()
        elif ch=='4': show_summary()
        elif ch=='5': break
        else: print("Invalid")

if __name__=="__main__":
    main()
