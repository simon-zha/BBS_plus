# BBS Signatures used in verifiable credentials and their variants

## Project Video Demo：

https://youtu.be/vm_nvwcjvN0

## Project Video Introduction：

https://youtu.be/fGHyY1-nruA

## Project Overview

This project implements the BBS+ signature scheme and extends it with Threshold Signature and Weak Partially-Blind Signature functionalities. BBS+ signatures are widely used in Verifiable Credentials (VCs) and Decentralized Identity (DID) due to their ability to sign message vectors and support efficient zero-knowledge proofs.

Traditional digital signature schemes suffer from single points of failure and privacy leakage risks. This project's threshold signature mechanism enhances system security and fault tolerance by distributing signing authority across multiple servers using Shamir Secret Sharing. Concurrently, the weak partially-blind signature allows users to obtain signatures without revealing all information to the signers, thereby protecting user privacy during credential issuance.

## Features

*   **BBS+ Core Signature:** Implements the Gen, Sign, and Verify algorithms for BBS+ signatures.
*   **Threshold BBS+ Signature:**
    *   Implements distributed key generation based on Shamir Secret Sharing.
    *   Supports (t, n) threshold configuration, requiring at least `t` servers to cooperate for a valid signature.
    *   Ensures fairness and security in multi-party computation through a commit-reveal mechanism.
*   **Weak Partially-Blind Signature:**
    *   Allows clients to obtain signatures without revealing partial message content to the signers.
    *   Supports separation of public information (`public_info`) and private information (`private_info`) within messages.
*   **BLS12-381 Elliptic Curve:** Underlying cryptographic operations are based on the BLS12-381 curve, providing 128-bit security strength.
*   **Performance Benchmarking:** Includes detailed performance testing scripts to evaluate the efficiency of curve operations, key generation, threshold signing, and verification.
*   **Modular Design:** Clear code structure with independent and reusable functional modules (e.g., curve operations, commitment, threshold protocol).

## Project Structure
```
new_bbs_plus/
├── benchmark/
│ └── benchmark.py # erformance benchmarking script
├── bbs/
│ ├── bbs_plus.py # Core BBS+ signature algorithm implementation
│ ├── commitment.py # Commitment mechanism (FCom) implementation
│ ├── curve.py # Elliptic curve operations (BLS12-381) implementation
│ └── threshold.py # Threshold BBS+ and Weak Partially-Blind Signature protocol implementation
├── test/
│ ├── client.py # Client simulation, interacts with servers
│ └── server.py # Server simulation, participates in threshold signing
└── README.md # Project README file
```
## Installation

1.  **Clone the repository:**

```bash
    git clone https://github.com/simon-zha/BBS_plus.git
    cd BBS_plus
```

2.  **Install Python dependencies:**

```bash
    pip install py_ecc
```

## Usage

This section details how to use the functionalities provided by this project. You can choose to directly call the Python API for programmatic use, or run the distributed system examples to experience the interaction between clients and servers.

### 1. Programmatic Usage (Python API)

This section demonstrates how to directly interact with the core cryptographic modules provided by this project.

#### 1.1. Basic BBS+ Signatures

The BBSPlus class provides the fundamental BBS+ signature generation and verification functionalities.

```PYTHON
from bbs.bbs_plus import BBSPlus
from bbs.curve import BilinearGroup 

# 1. Initialize BBSPlus
bbs = BBSPlus()


# 2. Generate Keys
# message_count specifies the maximum number of messages that can be signed.
message_count = 3
secret_key, public_key = bbs.gen(message_count)

print("BBS+ Keys Generated:")
# public_key['H'] is a list of G1 points, public_key['X'] is a G2 point.
# For display, you might want to serialize them:
# group = BilinearGroup()
# print(f"Public Key X: {group.serialize_g2_point(public_key['X'])}")
# print(f"Public Key H[0]: {group.serialize_g1_point(public_key['H'][0])}")

# 3. Sign Messages
messages = [123, 456, 789]
# Messages must be integers
signature = bbs.sign(secret_key, messages, public_key)

print("\nBBS+ Signature Generated:")
# signature['A'] is a G1 point, signature['e'] and signature['s'] are scalars.
# print(f"Signature A: {group.serialize_g1_point(signature['A'])}")
# print(f"Signature e: {signature['e']}")
# print(f"Signature s: {signature['s']}")

# 4. Verify Signature
is_valid = bbs.verify(public_key, messages, signature)
print(f"\nBBS+ Signature Valid: {is_valid}")
```

#### 1.2. Threshold BBS+ Signatures

The FormalThresholdBBSPlus class implements the multi-party threshold signature protocol. For simplified programmatic usage in a single-process simulation or testing environment, the formal_threshold_sign method encapsulates the entire client-server interaction.

Note: In a real-world distributed system, the client and server roles would be separated, communicating over a network. The test/client.py and test/server.py scripts provide a concrete example of this distributed setup.

```PYTHON
from bbs.threshold import FormalThresholdBBSPlus
from bbs.bbs_plus import BBSPlus
from bbs.curve import BilinearGroup

# --- Configuration ---
n_servers = 4  
# Total number of servers
t_threshold = 3 
# Minimum number of servers required to sign
message_count = 2 
# Number of messages to be signed
messages_to_sign = [100, 200]

# Simulate selected parties (e.g., the first 't' servers)
selected_parties_ids = list(range(1, t_threshold + 1))

# --- 1. System Setup (Typically done once by a trusted party) ---
# FormalThresholdBBSPlus will generate the global public key and distributed key shares.
# In a real system, each server would receive its share securely.
threshold_bbs_system = FormalThresholdBBSPlus(n_servers, t_threshold)
setup_data = threshold_bbs_system.setup(message_count)
global_public_key = setup_data['public_key']

print("Threshold BBS+ System Setup Complete.")
# print(f"Global Public Key X: {BilinearGroup().serialize_g2_point(global_public_key['X'])}")

# --- 2. Perform Threshold Signing (using the high-level wrapper) ---
# The `formal_threshold_sign` method simulates the entire multi-party protocol
# within a single call, assuming the orchestrator has access to all party data.
client_id = "example_client"
final_threshold_signature = threshold_bbs_system.formal_threshold_sign(
    client_id, messages_to_sign, selected_parties_ids
)

print("\nFinal Threshold Signature Generated:")
# print(f"Signature A: {BilinearGroup().serialize_g1_point(final_threshold_signature['A'])}")
# print(f"Signature e: {final_threshold_signature['e']}")
# print(f"Signature s: {final_threshold_signature['s']}")

# --- 3. Verify the Final Signature (using basic BBSPlus) ---
bbs_verifier = BBSPlus()
is_valid_threshold_sig = bbs_verifier.verify(global_public_key, messages_to_sign, final_threshold_signature)
print(f"\nFinal Threshold Signature Valid: {is_valid_threshold_sig}")

# --- Weak Partially-Blind Threshold Signing Example ---
# This also uses the `formal_threshold_sign` method with additional parameters.
# `public_info` and `private_info` are parts of the `messages_to_sign`.
# For example, if messages_to_sign = [100, 200], public_info = [100], private_info = [200]
public_info = [messages_to_sign[0]]
private_info = [messages_to_sign[1]]

# Alpha and Beta are blinding factors, typically generated by the client.
# In the `formal_threshold_sign` wrapper, these are passed through.
# The protocol internally sums up individual party's alpha_i and beta_i.
alpha_blinding = 12345
# Example client-side blinding factor
beta_blinding = 67890
# Example client-side blinding factor

print("\n--- Initiating Weak Partially-Blind Threshold Signing ---")
blind_signature = threshold_bbs_system.formal_threshold_sign(
    client_id,
    messages_to_sign,
    selected_parties_ids,
    public_info=public_info,
    private_info=private_info,
    alpha=alpha_blinding,
    beta=beta_blinding
)

print("\nWeak Partially-Blind Signature Generated:")
# print(f"Blind Signature A: {BilinearGroup().serialize_g1_point(blind_signature['A'])}")
# print(f"Blind Signature e: {blind_signature['e']}")
# print(f"Blind Signature s: {blind_signature['s']}")
# Verify the blind signature (verification is the same as regular BBS+)
is_valid_blind_sig = bbs_verifier.verify(global_public_key, messages_to_sign, blind_signature)
print(f"\nWeak Partially-Blind Signature Valid: {is_valid_blind_sig}")
```

### 2. Running Servers

You need to start multiple server instances to simulate the threshold signature environment. Each server should run on a different port.

**Example (4 servers, threshold 3):**

Open 4 separate terminal windows and run:

```bash
# Terminal 1 for Server 1
python server.py --id 1 --n 4 --t 3 --port 8001

# Terminal 2 for Server 2
python server.py --id 2 --n 4 --t 3 --port 8002

# Terminal 3 for Server 3
python server.py --id 3 --n 4 --t 3 --port 8003

# Terminal 4 for Server 4
python server.py --id 4 --n 4 --t 3 --port 8004
```

### 3. Running Client

Run the client script in another terminal window. The client will automatically perform system initialization, standard threshold signing, verification, weak partially-blind signing, and verification processes.

```bash
# Terminal 5 for Client
python client.py
```

The client's output will show the progress and results of each step, including the success or failure of signature generation and verification.

### 4. Running Performance Benchmarks

To evaluate the algorithm's performance, you can run the benchmarking script.

```BASH
python benchmark/benchmark.py
```

This script will test the average time for curve operations, key generation, threshold signing, and verification, and output a detailed performance report.

## Technical Details

- Elliptic Curve: Uses the py_ecc library to implement G1 and G2 group operations and bilinear pairings on the BLS12-381 curve.
- Shamir Secret Sharing: Used to split the master secret key x into n shares and supports reconstruction from t shares.
- Commitment Mechanism (FCom): Implements a collision-resistant commit-reveal protocol to ensure the integrity and consistency of random numbers in multi-party computation.
- Zero Share Function (FZero): Used to securely generate random shares that sum to zero, preventing bias attacks.
- Two-Party Multiplication Function (FMul2P): Provides a secure two-party multiplication protocol, supporting complex multi-party computations.

## Contributions

This project was completed by [
    Liang zhang,
    Dengjie Deng,
    Junwei Tang,
    Xiaojun Li,
    Linxi Wang
].
