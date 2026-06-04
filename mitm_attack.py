# mitm_attack.py
from dh_core import *

def mitm_simulation():
    p, g = generate_parameters()

    # Alice & Bob private keys
    a = generate_private_key(p)
    b = generate_private_key(p)

    # Attacker private key
    m = generate_private_key(p)

    # Public keys
    A = generate_public_key(g, a, p)
    B = generate_public_key(g, b, p)
    M = generate_public_key(g, m, p)

    # Attacker intercepts
    shared_A = generate_shared_key(M, a, p)
    shared_B = generate_shared_key(M, b, p)

    return shared_A, shared_B