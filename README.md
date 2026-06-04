# HashGuard

Enhanced Diffie-Hellman Security through a hash-based key authentication mechanism.

## What this project demonstrates

- Standard Diffie-Hellman key exchange as the baseline
- A simulated Man-in-the-Middle (MITM) attack against the baseline protocol
- A SHA-256-based authentication layer added after shared-key generation
- Experimental evaluation of attack success, detection, verification accuracy, execution time, and computational overhead

## Files

- `dh_core.py` - core Diffie-Hellman functions
- `mitm_attack.py` - MITM attack simulation
- `auth_layer.py` - SHA-256 hashing and authentication exchange
- `evaluation.py` - randomized benchmarking and CSV export
- `main.py` - single CLI entry point for all modes

## Requirements

- Python 3.11.9
- No external packages are required

## How to run

From the project folder:

```bash
python3 main.py standard
python3 main.py mitm
python3 main.py auth
python3 main.py evaluate
```

## Evaluation mode

The evaluation mode runs many randomized sessions and prints a metrics table.

To save the results as CSV:

```bash
python3 main.py evaluate --trials 500 --csv evaluation_results.csv
```

## Metrics reported

- Attack Success Rate
- Detection Rate
- Key Verification Accuracy
- Execution Time
- Computational Overhead

## Notes

- The Diffie-Hellman core mathematics is unchanged.
- The authentication layer is intentionally lightweight and designed for a mini-project demonstration.
- The current parameter set uses a larger prime and primitive root to reduce accidental collisions in the simulation.
