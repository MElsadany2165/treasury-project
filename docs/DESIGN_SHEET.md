# Treasury Project — Design Sheet (ICS505)

---

## 1. Group & Member Identifiers

- **Group Value (`GROUP`)**: `5-12-23`
- **Group Members & Assigned Roles**:
  - **John**: Security Infrastructure, Handshake, AES-256-GCM Framing, Integration, Attacks (A1), and Streamlit Dashboard.
  - **Yassin**: Member Registration, Zero-Knowledge Login (Interactive & Non-Interactive), Signed Requests, and Replay Protection.
  - **Divan**: Threshold Cryptography, Shamir Secret Sharing, Feldman Commitments, AES-256-GCM Vault Encryption, Chaum-Pedersen Verifiable Partial Decryption, and Attack A5.
  - **Essam**: Private Voting, Spending Proposals, Encrypted Ballots, Homomorphic Ciphertext Aggregation, Threshold Tally Decryption, Spending Approval, and Bonus Attack A7.

---

## 2. Table of System Values

| Value | Notation / Description | Who Chooses It | Who Knows It | When Created | Visibility |
|---|---|---|---|---|---|
| Domain parameters | $p, q, g$ (RFC 3526 Group 14) | Standard (RFC) | Public (All) | Pre-computation | Public |
| Group Identifier | `GROUP` | Group members | Public (All) | Project setup | Public |
| Founder Keypair | $(sk_{F}, pk_{F})$ on P-256 | Founder | $sk_{F}$: Founder only; $pk_{F}$: All | Setup | Private key secret, public key public |
| Certificates | `{"group", "name", "public_key", "expires", "sig"}` | Founder | Signer & Verifiers (All) | Setup | Public |
| Program Long-Term Keys | $(sk_{S}, pk_{S})$, $(sk_{Mi}, pk_{Mi})$ on P-256 | Server, Member $M_i$ | Owning program only | Setup | Private keys secret, public certs public |
| Ephemeral Handshake Keys | $x, y \in \mathbb{Z}_{\text{order}}$, $X=xP, Y=yP$ | Member ($x$), Server ($y$) | Generator only ($x, y$); $X, Y$ shared | Per connection handshake | Ephemerals secret, points $X, Y$ exchanged |
| ECDH Shared Secret | $S = xY = yX = xyP$ | Jointly by Member & Server | Member & Server | End of handshake | Secret (erased after session) |
| Session Keys | $K_{m2s}, K_{s2m}$ (32 bytes each via HKDF) | HKDF-SHA256 | Member & Server | End of handshake | Secret |
| AES-GCM Nonce Counters | 96-bit big-endian counter (starts at 0) | Sender & Receiver | Member & Server | Per frame | Transmitted in clear frame prefix |
| Login Secret | $x_M \in \mathbb{Z}_q$ | Member $M_i$ | Member $M_i$ only | Setup / First run | Secret |
| Login Public Value | $X_M = g^{x_M} \bmod p$ | Member $M_i$ | Member $M_i$, Server | Registration | Public |
| Interactive Login Commitment | $k \in \mathbb{Z}_q$, $R = g^k \bmod p$ | Member | Member ($k$), Server ($R$) | Per login attempt | $k$ secret, $R$ public |
| Interactive Login Challenge | $e \in \{0, 1\}^{128}$ | Server | Server & Member | Per login attempt | Public |
| Interactive Login Response | $z = k + e \cdot x_M \bmod q$ | Member | Member & Server | Per login attempt | Public |
| Non-Interactive Login Nonce | $N \in \{0, 1\}^{128}$ | Server | Server & Member | Per login attempt | Public |
| Request Sequence Number | `seq` (strictly increasing) | Member | Member & Server | Per signed request | Public |
| Master Vault Secret | $s \in \mathbb{Z}_q$ | Founder | Founder (erased after setup) | Setup | Strictly secret (never stored) |
| Shamir Polynomial Coeffs | $a_1, \dots, a_{t-1} \in \mathbb{Z}_q$ | Founder | Founder (erased after setup) | Setup | Strictly secret (erased) |
| Member Secret Shares | $s_i = f(i) \bmod q$ | Founder | Member $M_i$ only | Setup | Secret to Member $i$ |
| Feldman Commitments | $C_j = g^{a_j} \bmod p$ ($h = C_0$) | Founder | Public (All) | Setup | Public |
| Member Verification Keys | $h_i = \prod C_j^{i^j} \bmod p$ | Computed from $C_j$ | Public (All) | Setup | Public |
| Ephemeral Vault Mask | $u \in \mathbb{Z}_q$, $m = g^u \bmod p$ | Founder | Founder (erased after setup) | Setup | $u$ secret (erased), $m$ recovered at open |
| Vault ElGamal Ciphertext | $c_1 = g^r \bmod p, c_2 = m \cdot h^r \bmod p$ | Founder | Server & Members | Setup | Public |
| Vault Symmetric File Key | $K_{\text{vault}} = \text{HKDF}(m)$ (32 bytes) | Founder / Opening set | Founder & Combining Server | Setup / Opening | Secret |
| Partial Decryption Share | $d_i = c_1^{s_i} \bmod p$ | Member $M_i$ | Member $M_i$ & Server | Opening | Public |
| Decryption Share Proof | $w \in \mathbb{Z}_q, T_1 = g^w, T_2 = c_1^w, z = w + e s_i$ | Member $M_i$ | Member $M_i$ & Server | Opening | $w$ secret, $(T_1, T_2, z)$ public |
| Lagrange Coefficients | $\lambda_i = \prod_{j \ne i} j (j - i)^{-1} \bmod q$ | Server | Server | Opening | Public |
| Spending Vote Identifier | `vote_number` (integer) | Server | Public (All) | Proposal | Public |
| Ballot Ephemeral Randomness | $r \in \mathbb{Z}_q$ | Member $M_i$ | Member $M_i$ only | Per vote cast | Secret |
| Encrypted Ballot | $c_1 = g^r \bmod p, c_2 = g^v \cdot h^r \bmod p$ | Member $M_i$ | Public (All) | Per vote cast | Public (individual vote hidden) |
| Homomorphic Aggregate | $C_1 = \prod c_{1,k}, C_2 = \prod c_{2,k}$ | Server | Server & Members | Tally aggregation | Public |
| Tally Partial Decryption | $d_{i,\text{tally}} = C_1^{s_i} \bmod p$ | Member $M_i$ | Member $M_i$ & Server | Tally opening | Public |
| Recovered Yes Vote Count | $T = \sum v_k \in \{0, \dots, n\}$ | Server | Public (All) | Tally combination | Public |

---

## 3. Message Flows of Each Milestone

### Milestone 1: Authenticated Handshake & Login
```text
Member M1                                                           Server
   |                                                                  |
   | --- 1. {"cert": cert_M1, "X": X} ------------------------------> | (verify cert_M1)
   | <--- 2. {"cert": cert_S, "Y": Y, "sig": sig_S(["hs-server"])} - | (verify cert_S, sig_S)
   | --- 3. {"sig": sig_M1(["hs-member"])} ------------------------> | (verify sig_M1)
   |                                                                  |
   | [ Derive K_m2s, K_s2m via HKDF(ECDH(x, Y), transcript_hash) ]    |
   | ======== Transition to AES-256-GCM Encrypted Frames ============ |
   |                                                                  |
   | --- Encrypted {"op": "register", "X_M": X_M} ------------------->| (store X_M)
   | <--- Encrypted {"ok": true} ------------------------------------ |
   |                                                                  |
   | --- Encrypted {"op": "login-init", "R": R} --------------------->| (choose challenge e)
   | <--- Encrypted {"challenge": e} -------------------------------- |
   | --- Encrypted {"op": "login-finish", "z": z} ------------------->| (check g^z == R * X_M^e)
   | <--- Encrypted {"ok": true, "msg": "login OK"} ----------------- |
   |                                                                  |
   | --- Encrypted {"op": "request", request: {op, seq, body, sig}} ->| (verify sig, seq > last_seq)
   | <--- Encrypted {"ok": true, "msg": "added to ledger"} ---------- |
```

### Milestone 2: Verifiable Threshold Vault Opening
```text
Member Mi                                                           Server
   |                                                                  |
   | --- Encrypted {"op": "open_vault_request"} --------------------->| (server broadcasts c1, c2)
   |                                                                  |
   | [ Member computes d_i = c1^s_i, proof (T1, T2, z) ]              |
   | --- Encrypted {"op": "vault-share", d_i, T1, T2, z} ------------>| (verify Chaum-Pedersen proof:
   |                                                                  |  g^z == T1 * h_i^e and
   |                                                                  |  c1^z == T2 * d_i^e)
   |                                                                  |
   | [ Once t=3 valid shares collected: ]                             |
   | [ Server computes lambda_i, D = prod(d_i^lambda_i), m = c2 / D ] |
   | [ Derives vault key from m via HKDF; decrypts AES-GCM vault ]    |
```

### Milestone 3: Encrypted Spending Vote (Essam)
```text
Member M1 (Proposer)                                                Server
   |                                                                  |
   | --- Signed Proposal: {"op": "propose_spending", body} ----------> | (assigns vote_number)
   |                                                                  |
Members M1..Mn                                                      Server
   |                                                                  |
   | [ Each computes c1 = g^r, c2 = g^v * h^r, signs ballot ]         |
   | --- Encrypted {"op": "ballot", vote_number, c1, c2, sig} ------> | (verify signature, prevent duplicates)
   |                                                                  |
   | [ Server aggregates C1 = prod(c1), C2 = prod(c2) ]               |
   |                                                                  |
Members M1, M2, M3 (3 of 5)                                         Server
   |                                                                  |
   | --- Threshold Decryption Shares for C1 with proofs ------------> | (verify proofs)
   |                                                                  |
   | [ Server computes m_tally = C2 * D^(-1) = g^T mod p ]            |
   | [ Server tests T in 0..n: discovers total YES votes T ]          |
   | [ Decision: APPROVED if T >= 3, else REJECTED ]                  |
```

---

## 4. Attack Summaries (Mallory's Goal, Weakness, and Fix)

- **A1 — Unsigned Handshake (Mandatory)**:
  - **Goal**: Intercept communications between M1 and the server, reading M1's login and requests in cleartext.
  - **Weakness**: Handshake messages omit ECDSA signatures (`--weak unsigned-handshake`), allowing Mallory to complete separate key exchanges with M1 and the server.
  - **Fix**: Both sides mutually sign the handshake transcript with their certified P-256 keys. M1 detects the invalid/missing server signature and terminates the connection.

- **A5 — Cheating Member (Mandatory)**:
  - **Goal**: Sabotage the threshold vault opening undetected by submitting a corrupted share $d_3 \cdot g \pmod p$.
  - **Weakness**: Server skips Chaum-Pedersen proof verification (`--weak no-proof`), causing vault decryption to fail with nobody able to identify the attacker.
  - **Fix**: Server verifies Chaum-Pedersen equality-of-discrete-logs proofs before accepting shares, identifies M3's failing proof, rejects M3, and completes decryption with M4.

- **A7 — Tampered Ballot (Essam's Bonus Attack)**:
  - **Goal**: Flip a member's NO ballot to YES without knowing the private key or decrypting the ciphertext.
  - **Weakness**: Ballots are not digitally signed (`--weak unsigned-ballots`), allowing Mallory to multiply $c_2 = g^0 h^r$ by $g \pmod p$, changing it to $g^1 h^r$.
  - **Fix**: Ballots are ECDSA-signed over `["ballot", GROUP, name, vote_number, c1, c2]`. Tampering with $c_2$ invalidates the signature, causing the server to reject the ballot.
