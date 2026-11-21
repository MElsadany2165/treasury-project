# Treasury Project — Cryptographic Security System

A complete implementation of the Treasury Security System for a student club's shared vault and funds, implementing Milestones 1, 2, 3, mandatory attacks A1 and A5, bonus attack A7, and an interactive Streamlit dashboard.

---

## Team Roles & Deliverables

- **John — Security Infrastructure, Integration and Streamlit**
  - Milestone 1: P-256 keys, founder-signed certificates, ephemeral authenticated ECDH handshake, HKDF-SHA256 session key derivation, AES-256-GCM framing with strict monotonic counters, tampered and replayed frame detection.
  - Mandatory Attack A1: Unsigned handshake MITM proxy using Mallory.
  - Streamlit Dashboard: Full interactive UI connecting to backend.
- **Yassin — Authentication and Signed Requests**
  - Milestone 1: Member registration with public login value $X_M$, interactive zero-knowledge Schnorr login ($R, e, z$), non-interactive login with fresh server nonces, ECDSA signed requests with replay-protected sequence numbers, and accepted request ledger.
- **Divan — Threshold Cryptography and Vault**
  - Milestone 2: $(t, n)$ Shamir secret sharing ($t=3, n=5$), Feldman coefficient commitments, member share verification ($g^{s_i} == h_i$), AES-256-GCM vault file encryption, Chaum-Pedersen verifiable partial decryption shares ($d_i, T_1, T_2, z$), and Lagrange interpolation combining valid shares without rebuilding master key $s$.
  - Mandatory Attack A5: Cheating member attack demonstration in weak mode (`--weak no-proof`) and secure mode.
- **Essam — Private Voting and Bonus Attack**
  - Milestone 3: Signed spending proposals with unique vote identifiers, ElGamal-style additive homomorphic encrypted yes/no ballots under vault key $h$, ECDSA ballot signatures, duplicate ballot rejection, homomorphic ciphertext aggregation ($C_1 = \prod c_1, C_2 = \prod c_2$), verifiable threshold tally decryption, and spending approval threshold check ($T \ge 3$).
  - Bonus Attack A7: Changed ballot attack multiplying $c_2$ by $g \pmod p$, demonstrating vote flip in weak mode (`--weak unsigned-ballots`) and signature rejection in secure mode.

---

## Cryptographic Parameters & Standards

- **Group**: RFC 3526 Group 14 (2048-bit MODP Group).
- **Subgroup**: Sophie Germain prime $p = 2q + 1$ with generator $g = 4$ of prime order $q$.
- **Subgroup Check**: Any group element $u$ satisfies $1 < u < p$ and $u^q \equiv 1 \pmod p$.
- **Elliptic Curves**: NIST P-256 (`secp256r1`) for ECDSA signatures and ephemeral ECDH.
- **Key Derivation**: HKDF-SHA256 with domain separation string `ICS505|<GROUP>|...`.
- **Symmetric Encryption**: AES-256-GCM with 96-bit monotonic counter nonces.

---

## Setup & Running

### 1. Requirements & Dependencies
Ensure Python 3.10+ is installed:
```bash
pip install cryptography ecdsa streamlit pytest
```

### 2. Founder Initialization
Initialize founder keys, member certificates, Shamir shares, Feldman commitments, and the encrypted vault:
```bash
python -m treasury.founder --t 3 --n 5
```

### 3. Run Automated Tests
Run the comprehensive test suite (28 unit and integration tests):
```bash
python -m pytest tests/test_login.py tests/test_certificates.py tests/test_channel.py tests/test_sharing.py tests/test_opening.py tests/test_voting.py tests/test_attacks.py -v
```

### 4. Run the Streamlit Dashboard
Launch the unified interactive web interface:
```bash
streamlit run streamlit_app.py
```

### 5. Running TCP Programs in Multiple Terminals

#### Terminal 1 — Treasury Server
```bash
python -m treasury.server --name server
```
*(To run with a deliberate weakness, use `--weak <name>`, e.g. `--weak unsigned-handshake` or `--weak no-proof` or `--weak unsigned-ballots`)*

#### Terminal 2 — Member Client (Interactive Login & Requests)
```bash
python -m treasury.member --name M1 --action login
python -m treasury.member --name M1 --action spend --amount 50 --reason "Refreshments"
```

#### Terminal 3 — Spending Proposal & Private Voting (Essam's Milestone 3)
```bash
python -m treasury.member --name M1 --action propose --amount 1500 --reason "Security Audit"
python -m treasury.member --name M1 --action vote --vote-number 1 --vote 1
python -m treasury.member --name M2 --action vote --vote-number 1 --vote 1
python -m treasury.member --name M3 --action vote --vote-number 1 --vote 0
```

---

## Attack Demonstrations

### Attack A1: Unsigned Handshake MITM Proxy (Mandatory)
- **Weak Mode**:
  ```bash
  # Terminal 1:
  python -m treasury.server --weak unsigned-handshake
  # Terminal 2:
  python -m treasury.mallory --attack A1 --weak unsigned-handshake
  # Terminal 3:
  python -m treasury.member --name M1 --port 6000 --weak unsigned-handshake
  ```
  Mallory intercepts the connection on port 6000, establishes two independent handshakes, decrypts frames, and logs M1's login and requests in cleartext. Mallory cannot forge M1's ECDSA-signed requests.
- **Secure Mode**:
  ```bash
  python -m treasury.mallory --attack A1
  python -m treasury.member --name M1 --port 6000
  ```
  M1 detects that Mallory cannot produce the server's valid certificate and signature, and immediately rejects the handshake!

### Attack A5: Cheating Member in Threshold Opening (Mandatory)
```bash
python -m treasury.mallory --attack A5
```
- In weak mode (`--weak no-proof`), M3 submits $d_3 \cdot g \pmod p$; the vault fails to open and nobody can tell who cheated.
- In secure mode, the server verifies Chaum-Pedersen proofs, catches M3's failing proof, rejects M3, and successfully opens the vault using shares from {M1, M2, M4}!

### Attack A7: Tampered Ballot (Essam's Bonus Attack)
```bash
python -m treasury.mallory --attack A7
```
- In weak mode (`--weak unsigned-ballots`), Mallory multiplies a NO ballot's $c_2$ by $g \pmod p$, turning $g^0 \cdot h^r$ into $g^1 \cdot h^r$, flipping the vote to YES without decryption!
- In secure mode, the server verifies the member's ECDSA signature over `["ballot", GROUP, name, vote_num, c1, c2]`, catches the modified ciphertext, and rejects the ballot!

---

## Defense & Oral Evaluation Questions

1. **Why fresh $x$ and $y$ for every connection protect old sessions if a long-term key is stolen later?**
   - **Forward Secrecy**: The session key is computed via Diffie-Hellman as $S = xY = yX = xyP$. Because $x$ and $y$ are ephemeral scalars generated independently for each connection and erased immediately upon disconnection, an attacker who steals the long-term private key later cannot compute $xyP$ from public transcripts $X$ and $Y$ (Computational Diffie-Hellman assumption).
2. **Why a login transcript tells the server nothing about $x_M$, even though the server sees $R, e, z$?**
   - **Zero-Knowledge Property**: The Schnorr identification scheme is honest-verifier zero-knowledge. Given public $X_M$, a simulator can pick random $z$ and $e$, and compute $R = g^z \cdot X_M^{-e} \pmod p$. The simulated distribution $(R, e, z)$ is identical to the real protocol transcript, proving that transcripts contain zero knowledge about $x_M$.
3. **Why multiplying the ballots adds the votes (Homomorphic Property)?**
   - Each ballot encrypts $v_k$ as $(c_{1,k}, c_{2,k}) = (g^{r_k}, g^{v_k} \cdot h^{r_k})$.
   - Modular multiplication yields:
     $$C_1 = \prod_{k=1}^n c_{1,k} = g^{\sum r_k} \pmod p$$
     $$C_2 = \prod_{k=1}^n c_{2,k} = g^{\sum v_k} \cdot h^{\sum r_k} = g^T \cdot h^{\sum r_k} \pmod p$$
   - When decrypted using threshold share combination, $D = C_1^s = h^{\sum r_k} \pmod p$ is eliminated, leaving $m_{tally} = C_2 \cdot D^{-1} = g^T \pmod p$, where $T = \sum v_k$ is the exact sum of yes votes.
4. **Why a member who encrypts $v = 5$ is not caught by this protocol, and what kind of proof would stop it?**
   - The ElGamal encryption allows any integer exponent in $g^v$. The aggregation simply computes $g^{\sum v_k}$. The server only checks if the final tally equals $g^T$ for $T \in [0, n]$. A single rogue member encrypting $v=5$ shifts the total without being detected unless individual ballots are constrained.
   - To stop this, each ballot would require a **Zero-Knowledge Disjunctive Proof (CDS proof / OR-proof)** proving that $v \in \{0, 1\}$ without revealing which one it is (i.e. proving knowledge of discrete log of $c_2/h^r$ with respect to $g$ is either $0$ or $1$).
