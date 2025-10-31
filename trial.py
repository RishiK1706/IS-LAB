#!/usr/bin/env python3
"""
Secure Payment Processing System
- Encryption: Diffie–Hellman shared secret → AES
- Integrity: SHA-512 hashing
- Signature: ElGamal signature on hash
- Roles: Customer, Merchant, Auditor
"""

import hashlib, random, time
from datetime import datetime
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# -------------------------
# Number theory utils
# -------------------------
def egcd(a, b):
    if b == 0: return (1, 0, a)
    x, y, g = egcd(b, a % b)
    return (y, x - (a // b) * y, g)

def modinv(a, m):
    x, y, g = egcd(a % m, m)
    if g != 1:
        raise ValueError("No modular inverse")
    return x % m

def is_probable_prime(n, k=8):
    if n < 2: return False
    if n % 2 == 0: return n == 2
    d, s = n-1, 0
    while d % 2 == 0: d //= 2; s += 1
    for _ in range(k):
        a = random.randrange(2, n-1)
        x = pow(a, d, n)
        if x == 1 or x == n-1: continue
        for __ in range(s-1):
            x = pow(x, 2, n)
            if x == n-1: break
        else: return False
    return True

def gen_prime(bits):
    while True:
        n = random.getrandbits(bits) | 1 | (1 << bits-1)
        if is_probable_prime(n): return n

# -------------------------
# Diffie–Hellman setup
# -------------------------
DH_BITS = 256
p = gen_prime(DH_BITS)
g = 2

def dh_keygen():
    priv = random.randrange(2, p-2)
    pub = pow(g, priv, p)
    return priv, pub

def dh_shared(pub_other, priv_self):
    return pow(pub_other, priv_self, p)

def sha256(b): return hashlib.sha256(b).digest()
def sha512(b): return hashlib.sha512(b).digest()

# -------------------------
# AES helpers
# -------------------------
def aes_encrypt(msg_bytes, key):
    cipher = AES.new(key, AES.MODE_CBC)
    return cipher.iv + cipher.encrypt(pad(msg_bytes, AES.block_size))

def aes_decrypt(ciphertext, key):
    iv, ct = ciphertext[:16], ciphertext[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ct), AES.block_size)

# -------------------------
# ElGamal signature
# -------------------------
def elgamal_keygen(bits=256):
    p = gen_prime(bits); g = 2
    x = random.randrange(2, p-2)
    y = pow(g, x, p)
    return {'p': p, 'g': g, 'x': x, 'y': y}

def elgamal_sign(h_bytes, priv):
    p, g, x = priv['p'], priv['g'], priv['x']
    H = int.from_bytes(h_bytes, 'big') % p
    while True:
        k = random.randrange(2, p-2)
        if egcd(k, p-1)[2] == 1: break
    r = pow(g, k, p)
    k_inv = modinv(k, p-1)
    s = (k_inv * (H - x*r)) % (p-1)
    return (r, s)

def elgamal_verify(h_bytes, sig, pub):
    p, g, y = pub['p'], pub['g'], pub['y']
    H = int.from_bytes(h_bytes, 'big') % p
    r, s = sig
    left = pow(g, H, p)
    right = (pow(y, r, p) * pow(r, s, p)) % p
    return left == right

# -------------------------
# Transaction store
# -------------------------
class Store:
    def __init__(self): self.data=[]; self.nextid=1
    def add(self, r): r['id']=self.nextid; self.nextid+=1; self.data.append(r)
    def pending(self): return [t for t in self.data if t['status']=="pending"]
    def processed(self): return [t for t in self.data if t['status']!="pending"]

store = Store()

# -------------------------
# Setup keys
# -------------------------
print("Generating keys...")
# Customer
c_priv, c_pub = dh_keygen()
elg_cust = elgamal_keygen()
# Merchant
m_priv, m_pub = dh_keygen()
print("Keys ready.")

# Shared secret (both compute same)
shared_cust = dh_shared(m_pub, c_priv)
shared_merc = dh_shared(c_pub, m_priv)
assert shared_cust == shared_merc
aes_key = sha256(shared_cust.to_bytes((shared_cust.bit_length()+7)//8,'big'))

# -------------------------
# Roles
# -------------------------
def customer_send():
    pt = input("\n[Customer] Enter payment details: ").encode()
    h = sha512(pt)
    sig = elgamal_sign(h, elg_cust)
    ct = aes_encrypt(pt, aes_key)
    record = {
        'cipher': ct.hex(),
        'hash': h.hex(),
        'sig': sig,
        'elg_pub': {'p': elg_cust['p'], 'g': elg_cust['g'], 'y': elg_cust['y']},
        'status':'pending',
        'ts_sent': datetime.now().isoformat()
    }
    store.add(record)
    print(f"[Customer] Sent tx id {record['id']}")

def merchant_process():
    for t in store.pending():
        print(f"\n[Merchant] Processing tx {t['id']}")
        ct = bytes.fromhex(t['cipher'])
        pt = aes_decrypt(ct, aes_key)
        h2 = sha512(pt).hex()
        sig_ok = elgamal_verify(bytes.fromhex(t['hash']), t['sig'], t['elg_pub'])
        ok = (h2 == t['hash']) and sig_ok
        t['status']="processed"
        t['ts_proc']=datetime.now().isoformat()
        t['merchant_ok']=ok
        t['revealed_plain']=pt.decode()
        print(f"[Merchant] Plain: {pt.decode()}")
        print(f"[Merchant] Hash match: {h2==t['hash']}  Signature ok: {sig_ok}")

def auditor_view():
    for t in store.processed():
        print(f"\n[Auditor] Tx {t['id']} status={t['status']}")
        print(" Received hash:",t['hash'][:16],"...")
        print(" Merchant hash check:", t.get('merchant_ok'))
        sig_ok = elgamal_verify(bytes.fromhex(t['hash']), t['sig'], t['elg_pub'])
        print(" Auditor signature check:", sig_ok)

def summary():
    print("\n=== Summary ===")
    for t in store.data:
        print(f"ID {t['id']} | status {t['status']} | hash {t['hash'][:12]}...")

# -------------------------
# Menu loop
# -------------------------
def main():
    while True:
        ch = input("""
1) Customer send tx
2) Merchant process
3) Auditor view
4) Summary
5) Exit
Choice: """)
        if ch=='1': customer_send()
        elif ch=='2': merchant_process()
        elif ch=='3': auditor_view()
        elif ch=='4': summary()
        elif ch=='5': break

if __name__=="__main__":
    main()
