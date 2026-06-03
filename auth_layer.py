# auth_layer.py
import hashlib

def create_hash(shared_key, identity):
    data = str(shared_key) + identity
    return hashlib.sha256(data.encode()).hexdigest()

def verify_hash(hash1, hash2):
    return hash1 == hash2

def exchange_and_verify(shared_A, shared_B, identity_A="Alice", identity_B="Bob"):
    alice_to_bob = create_hash(shared_A, identity_A)
    bob_to_alice = create_hash(shared_B, identity_B)

    alice_expected = create_hash(shared_A, identity_B)
    bob_expected = create_hash(shared_B, identity_A)

    alice_verified = verify_hash(alice_expected, bob_to_alice)
    bob_verified = verify_hash(bob_expected, alice_to_bob)

    return {
        "alice_to_bob": alice_to_bob,
        "bob_to_alice": bob_to_alice,
        "alice_verified": alice_verified,
        "bob_verified": bob_verified,
        "authenticated": alice_verified and bob_verified,
    }