from dh_core import *
from mitm_attack import mitm_simulation
from auth_layer import *
from evaluation import run_evaluation
import argparse

def run_standard_dh():
    p, g = generate_parameters()

    a = generate_private_key(p)
    b = generate_private_key(p)

    A = generate_public_key(g, a, p)
    B = generate_public_key(g, b, p)

    shared_A = generate_shared_key(B, a, p)
    shared_B = generate_shared_key(A, b, p)

    print("Mode: Standard Diffie-Hellman")
    print("Shared Key A:", shared_A)
    print("Shared Key B:", shared_B)
    print("Keys match:", shared_A == shared_B)


def run_mitm_dh():
    shared_A, shared_B = mitm_simulation()

    print("Mode: Diffie-Hellman with MITM Attack")
    print("Alice's derived key:", shared_A)
    print("Bob's derived key:", shared_B)
    print("Attack succeeded:", shared_A != shared_B)


def run_authenticated_dh():
    p, g = generate_parameters()

    a = generate_private_key(p)
    b = generate_private_key(p)

    A = generate_public_key(g, a, p)
    B = generate_public_key(g, b, p)

    shared_A = generate_shared_key(B, a, p)
    shared_B = generate_shared_key(A, b, p)

    exchange = exchange_and_verify(shared_A, shared_B, "Alice", "Bob")

    print("Mode: Diffie-Hellman with Hash Authentication")
    print("Shared Key A:", shared_A)
    print("Shared Key B:", shared_B)
    print("Alice verified Bob:", exchange["alice_verified"])
    print("Bob verified Alice:", exchange["bob_verified"])
    print("Authenticated session:", exchange["authenticated"])

def main():
    parser = argparse.ArgumentParser(description="HashGuard Diffie-Hellman demo modes")
    parser.add_argument(
        "mode",
        choices=["standard", "mitm", "auth", "evaluate"],
        help="Choose which Diffie-Hellman mode to run",
    )
    parser.add_argument(
        "--trials",
        type=int,
        default=500,
        help="Number of randomized sessions to use in evaluation mode",
    )
    parser.add_argument(
        "--csv",
        default=None,
        help="Optional path to save the evaluation report as CSV",
    )

    args = parser.parse_args()

    if args.mode == "standard":
        run_standard_dh()
    elif args.mode == "mitm":
        run_mitm_dh()
    elif args.mode == "evaluate":
        run_evaluation(args.trials, args.csv)
    else:
        run_authenticated_dh()


if __name__ == "__main__":
    main()