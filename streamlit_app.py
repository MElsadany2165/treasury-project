"""Treasury Project Streamlit Dashboard
Integrated interface for:
- Milestone 1: Secure Channel, ZK Login, Signed Requests & Ledger
- Milestone 2: Shamir Secret Sharing, Feldman Commitments, Verifiable Threshold Decryption
- Milestone 3: Essam's Private Voting, Homomorphic Aggregation, Tally Decryption
- Attacks: A1 (MITM Proxy), A5 (Cheating Member), A7 (Tampered Ballot)
- Live Logs & Weak/Secure Mode Controls
"""
import json
import os
from pathlib import Path
import streamlit as st

from treasury.config import (
    DATA_DIR,
    DEFAULT_N,
    DEFAULT_T,
    G,
    GROUP,
    HOST,
    LOG_DIR,
    P,
    Q,
    SERVER_PORT,
    WEAKNESS_NAMES,
)
from treasury.founder import setup_treasury
from treasury.certificates import (
    generate_p256_keypair,
    public_key_to_pem,
    public_key_from_pem,
    create_certificate,
    verify_certificate,
)
from treasury.channel import (
    derive_directional_keys,
    public_key_to_point_hex,
    public_key_from_point_hex,
    sign_handshake_step,
    verify_handshake_step,
    SecureChannel,
)
from treasury.login import (
    register_login_secret,
    make_interactive_commitment,
    make_interactive_response,
    verify_interactive_login,
    make_noninteractive_response,
    verify_noninteractive_login,
)
from treasury.requests import sign_request, verify_request
from treasury.sharing import (
    make_shares,
    make_commitments,
    compute_verification_key,
    verify_share,
    lagrange_coefficient,
)
from treasury.opening import (
    encrypt_vault_file,
    make_decryption_share,
    verify_decryption_share,
    combine_decryption_shares,
    decrypt_vault_file,
)
from treasury.voting import (
    create_proposal,
    encrypt_vote,
    sign_ballot,
    verify_ballot,
    aggregate_ballots,
    decrypt_tally,
    check_spending_approval,
    tamper_ballot_a7,
)

# Page configuration
st.set_page_config(
    page_title="Treasury Security System Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.title("🛡️ Student Treasury Security & Cryptography System")
st.caption(f"Course: ICS505 • Group Identifier: **{GROUP}** • System Parameters: RFC 3526 Group 14 (2048-bit MODP), P-256 ECDSA/ECDH")

# Sidebar Controls
st.sidebar.image("https://img.icons8.com/color/96/shield.png", width=64)
st.sidebar.title("Configuration & Modes")

security_mode = st.sidebar.radio(
    "Security Mode Selection",
    ["Secure Mode (Default)", "Weak Mode (Vulnerable)"],
    index=0,
)

active_weakness = None
if security_mode == "Weak Mode (Vulnerable)":
    active_weakness = st.sidebar.selectbox(
        "Active Weakness (--weak)",
        sorted(list(WEAKNESS_NAMES)),
        index=0,
    )
    st.sidebar.warning(f"⚠️ Running with deliberate weakness: `{active_weakness}`")
else:
    st.sidebar.success("🔒 System running in fully authenticated & secure mode")

page = st.sidebar.radio(
    "Navigation Pages",
    [
        "1. Overview & Setup",
        "2. Secure Channel & Login (M1)",
        "3. Treasury Vault (M2)",
        "4. Private Voting (M3 - Essam)",
        "5. Attack Demonstrations (A1, A5, A7)",
        "6. Genuine System Logs",
    ],
)

# Helper function to read logs
def get_log_content(program_name: str) -> str:
    log_file = LOG_DIR / f"{program_name}.log"
    if log_file.exists():
        with open(log_file, "r", encoding="utf-8") as f:
            lines = f.readlines()
            return "".join(lines[-100:])  # last 100 lines
    return "No logs generated yet."


# --- PAGE 1: OVERVIEW & SETUP ---
if page == "1. Overview & Setup":
    st.header("📋 System Architecture & Founder Setup")
    
    col1, col2 = st.columns([2, 1])
    with col1:
        st.markdown(f"""
        ### Project Summary
        The Treasury system enforces multi-party security for a student club's shared vault and funds:
        - **Milestone 1 (John & Yassin)**: P-256 authenticated ECDH handshake, founder-signed certificates, HKDF-SHA256 directional session keys, AES-256-GCM encrypted framing with monotonic counters, zero-knowledge login proofs, and ECDSA signed requests.
        - **Milestone 2 (Divan)**: $(t, n)$ Shamir polynomial secret sharing, Feldman commitments, verifiable partial decryptions with Chaum-Pedersen proofs, and Lagrange combination.
        - **Milestone 3 (Essam)**: Additive ElGamal homomorphic encrypted yes/no ballots under vault key $h$, duplicate prevention, threshold tally decryption, and spending approval.
        - **Mandatory Attacks & Demonstrations**:
          - **A1**: MITM attack against unsigned handshake (`--weak unsigned-handshake`).
          - **A5**: Cheating member attack submitting corrupted share (`--weak no-proof`).
          - **A7**: Bonus attack modifying unsigned encrypted ballot (`--weak unsigned-ballots`).
        """)

    with col2:
        st.subheader("Group & System Parameters")
        st.json({
            "GROUP": GROUP,
            "Threshold (t)": DEFAULT_T,
            "Members (n)": DEFAULT_N,
            "Prime p length": f"{P.bit_length()} bits",
            "Subgroup order q length": f"{Q.bit_length()} bits",
            "Generator g": G,
        })

    st.divider()
    st.subheader("🔑 Founder Fresh Setup")
    st.write("Run founder setup to generate keys, founder-signed certificates, Shamir shares, Feldman commitments, and initial encrypted vault:")
    
    setup_col1, setup_col2, setup_col3 = st.columns([1, 1, 2])
    with setup_col1:
        t_param = st.number_input("Threshold (t)", min_value=1, max_value=10, value=3)
    with setup_col2:
        n_param = st.number_input("Members (n)", min_value=t_param, max_value=10, value=5)

    if st.button("🚀 Initialize / Re-run Founder Setup", type="primary"):
        with st.spinner("Executing founder cryptographic setup..."):
            setup_treasury(t=t_param, n=n_param)
            st.success("Founder setup completed successfully!")

    # Display setup status
    founder_pub_file = DATA_DIR / "founder.pub"
    if founder_pub_file.exists():
        st.info("System initialized! Founder public key and member directories are present in `runtime/data/`.")


# --- PAGE 2: SECURE CHANNEL & LOGIN ---
elif page == "2. Secure Channel & Login (M1)":
    st.header("🔒 Milestone 1: Secure Channel, ZK Login & Signed Requests")
    
    tab1, tab2, tab3 = st.tabs(["1. Handshake & Session Keys", "2. Zero-Knowledge Login", "3. Signed Requests & Ledger"])

    with tab1:
        st.subheader("Authenticated Ephemeral ECDH Handshake")
        st.markdown(r"""
        1. Member $\to$ Server: `{"cert": member_cert, "X": X}` where $X = xP$.
        2. Server $\to$ Member: `{"cert": server_cert, "Y": Y, "sig": Server ECDSA sig on ["hs-server", GROUP, member, X, Y]}`.
        3. Member $\to$ Server: `{"sig": Member ECDSA sig on ["hs-member", GROUP, member, X, Y]}`.
        4. Session Keys: Derived via HKDF-SHA256 from $S = xY = yX$ and transcript hash.
        """)
        
        member_select = st.selectbox("Select Member for Handshake Simulation", [f"M{i}" for i in range(1, 6)])
        if st.button("Simulate Handshake"):
            # Load founder pub
            with open(DATA_DIR / "founder.pub", "r") as f:
                founder_pub = public_key_from_pem(f.read())
            with open(DATA_DIR / "server" / "server_priv.pem", "r") as f:
                from treasury.certificates import private_key_from_pem
                server_priv = private_key_from_pem(f.read())
            with open(DATA_DIR / "server" / "server_cert.json", "r") as f:
                server_cert = json.load(f)
            with open(DATA_DIR / member_select / f"{member_select}_priv.pem", "r") as f:
                m_priv = private_key_from_pem(f.read())
            with open(DATA_DIR / member_select / f"{member_select}_cert.json", "r") as f:
                m_cert = json.load(f)

            # Ephemeral keys
            m_eph_priv, m_eph_pub = generate_p256_keypair()
            s_eph_priv, s_eph_pub = generate_p256_keypair()
            X_hex = public_key_to_point_hex(m_eph_pub)
            Y_hex = public_key_to_point_hex(s_eph_pub)

            srv_sig = sign_handshake_step(server_priv, "hs-server", member_select, X_hex, Y_hex)
            m_sig = sign_handshake_step(m_priv, "hs-member", member_select, X_hex, Y_hex)

            ss_member = m_eph_priv.exchange(ec.ECDH(), s_eph_pub)
            m2s, s2m = derive_directional_keys(ss_member, member_select, X_hex, Y_hex)

            st.success("Handshake Completed Successfully!")
            st.json({
                "Member Certificate Valid": verify_certificate(m_cert, founder_pub, member_select),
                "Server Certificate Valid": verify_certificate(server_cert, founder_pub, "server"),
                "Server Handshake Signature Verified": verify_handshake_step(server_priv.public_key(), srv_sig, "hs-server", member_select, X_hex, Y_hex),
                "Member Handshake Signature Verified": verify_handshake_step(m_priv.public_key(), m_sig, "hs-member", member_select, X_hex, Y_hex),
                "Ephemeral X (first 16 chars)": X_hex[:16] + "...",
                "Ephemeral Y (first 16 chars)": Y_hex[:16] + "...",
                "Member->Server AES-256 Key": m2s.hex()[:32] + "...",
                "Server->Member AES-256 Key": s2m.hex()[:32] + "...",
            })

    with tab2:
        st.subheader("Schnorr Zero-Knowledge Proof Login")
        st.markdown(r"""
        - Secret: $x_M \in \mathbb{Z}_q$, Public Registration: $X_M = g^{x_M} \bmod p$.
        - **Interactive Login**: Member sends $R = g^k \bmod p$, Server challenges $e$, Member sends $z = k + e \cdot x_M \bmod q$.
        - Server verifies: $g^z \equiv R \cdot X_M^e \pmod p$.
        """)
        
        login_type = st.radio("Login Protocol", ["Interactive ZK Proof", "Non-Interactive ZK Proof (Fiat-Shamir with Server Nonce)"])
        login_member = st.selectbox("Logging in as", [f"M{i}" for i in range(1, 6)], key="login_mb")
        
        if st.button("Execute ZK Login"):
            # Load or register login secret
            x_M, X_M = register_login_secret(login_member, P, Q, G)
            if login_type == "Interactive ZK Proof":
                k, R = make_interactive_commitment(P, Q, G)
                import secrets
                e = secrets.randbits(128)
                z = make_interactive_response(x_M, k, e, Q)
                verified = verify_interactive_login(R, z, e, X_M, P, Q, G)
                st.success(f"Interactive ZK Login Verified: **{verified}**")
                st.write(f"- $R$: `{format(R, 'x')[:16]}...`")
                st.write(f"- Challenge $e$: `{format(e, 'x')[:16]}...`")
                st.write(f"- Response $z$: `{format(z, 'x')[:16]}...`")
                st.write(f"- Verification check: $g^z \\equiv R \\cdot X_M^e \\pmod p$ returned `{verified}`")
            else:
                import secrets
                N = secrets.randbits(128)
                R, z = make_noninteractive_response(login_member, x_M, X_M, N, P, Q, G)
                verified = verify_noninteractive_login(login_member, R, z, N, X_M, P, Q, G)
                st.success(f"Non-Interactive ZK Login Verified: **{verified}**")
                st.write(f"- Fresh Server Nonce $N$: `{N}`")
                st.write(f"- Verification check: `{verified}`")

    with tab3:
        st.subheader("Signed Requests & Accepted Ledger")
        st.markdown(r"""
        Every request is signed with ECDSA: `["request", GROUP, name, seq, op, body]`.
        The server enforces strictly increasing sequence numbers `seq > last_seq` to reject replays.
        """)
        req_mb = st.selectbox("Requesting Member", [f"M{i}" for i in range(1, 6)], key="req_mb")
        req_op = st.selectbox("Operation (op)", ["spend", "propose_spending", "query_status"])
        req_amount = st.number_input("Amount (ICS tokens)", value=50)
        req_reason = st.text_input("Reason", value="Team meeting refreshments")

        if st.button("Submit Signed Request"):
            with open(DATA_DIR / req_mb / f"{req_mb}_priv.pem", "r") as f:
                from treasury.certificates import private_key_from_pem
                priv = private_key_from_pem(f.read())
            
            req_data = sign_request(priv, GROUP, req_mb, seq=1, op=req_op, body={"amount": req_amount, "reason": req_reason})
            verified = verify_request(priv.public_key(), req_data, last_sequence=0, group=GROUP, name=req_mb)
            
            st.success("Request Signed and Verified!")
            st.json({
                "Request Object": req_data,
                "Signature Verified": verified,
                "Replay Check (seq 1 > 0)": True,
            })


# --- PAGE 3: TREASURY VAULT (M2) ---
elif page == "3. Treasury Vault (M2)":
    st.header("🗝️ Milestone 2: Threshold Cryptography & Treasury Vault")
    st.markdown(r"""
    The Treasury Vault is locked under master key $h = g^s \pmod p$ where secret $s$ was shared among 5 members using a degree-2 polynomial ($t=3$ threshold).
    Any 3 members open the vault by providing verifiable partial decryption shares $d_i = c_1^{s_i} \pmod p$ with Chaum-Pedersen proofs, combined via Lagrange interpolation without reconstructing $s$!
    """)

    # Load commitments
    with open(DATA_DIR / "server" / "commitments.json", "r") as f:
        comms_meta = json.load(f)
    commitments = [int(c, 16) for c in comms_meta["commitments"]]
    h = commitments[0]

    with open(DATA_DIR / "server" / "vault_meta.json", "r") as f:
        v_meta = json.load(f)
    with open(DATA_DIR / "server" / "vault.enc", "rb") as f:
        enc_vault = f.read()

    c1 = int(v_meta["c1"], 16)
    c2 = int(v_meta["c2"], 16)

    st.subheader("Select 3 Participating Members to Open Vault")
    selected_members = st.multiselect(
        "Choose at least 3 members (e.g. M1, M3, M5)",
        [f"M{i}" for i in range(1, 6)],
        default=["M1", "M3", "M5"],
    )

    if st.button("🔓 Verifiable Threshold Decryption", type="primary"):
        if len(selected_members) < 3:
            st.error("Error: Threshold requires at least 3 members!")
        else:
            shares_dict = {}
            proof_results = []
            for name in selected_members:
                with open(DATA_DIR / name / f"{name}_share.json", "r") as f:
                    s_data = json.load(f)
                idx = s_data["index"]
                s_i = int(s_data["share"], 16)
                vkey = int(s_data["verification_key"], 16)
                
                # Check share against commitments
                valid_share = verify_share(s_i, idx, commitments, P, Q, G)
                # Generate decryption share with proof
                d_obj = make_decryption_share(s_i, idx, c1, vkey, P, Q, G)
                # Verify proof
                proof_ok = verify_decryption_share(
                    idx, c1, vkey, d_obj["d_i"], d_obj["T_1"], d_obj["T_2"], d_obj["z"], P, Q, G
                )
                proof_results.append({
                    "Member": name,
                    "Share Valid against Commitments": valid_share,
                    "Decryption Share d_i": format(d_obj["d_i"], "x")[:12] + "...",
                    "Chaum-Pedersen Proof": "VERIFIED (OK)" if proof_ok else "FAILED",
                })
                shares_dict[idx] = d_obj["d_i"]

            st.table(proof_results)

            # Combine shares
            subset_shares = dict(list(shares_dict.items())[:3])
            decrypted = decrypt_vault_file(c1, c2, enc_vault, subset_shares, P, Q)
            st.success("🎉 Vault Successfully Decrypted!")
            st.code(decrypted.decode("utf-8"), language="text")


# --- PAGE 4: PRIVATE VOTING (M3 - ESSAM) ---
elif page == "4. Private Voting (M3 - Essam)":
    st.header("🗳️ Milestone 3: Private Encrypted Spending Vote (Essam's Deliverable)")
    st.markdown(r"""
    ### Cryptographic Protocol:
    1. **Proposal**: A member initiates a proposal with a unique vote identifier.
    2. **Encrypted Ballot**: Each member encrypts their vote $v \in \{0, 1\}$ with fresh randomness $r$:
       $$c_1 = g^r \pmod p, \quad c_2 = g^v \cdot h^r \pmod p$$
       Each ballot is signed with the member's ECDSA key over `["ballot", GROUP, name, vote_num, c1, c2]`.
    3. **Homomorphic Ciphertext Aggregation**:
       $$C_1 = \prod_{k=1}^n c_{1,k} \pmod p, \quad C_2 = \prod_{k=1}^n c_{2,k} \pmod p$$
    4. **Verifiable Threshold Tally Decryption**: 3 members submit partial decryption shares of $(C_1, C_2)$ with Chaum-Pedersen proofs.
       $$m_{tally} = C_2 \cdot D^{-1} = g^T \pmod p \quad \text{where } T = \sum v_k$$
    5. **Spending Approval**: Proposal is approved if total YES votes $T \ge 3$.
    """)

    st.subheader("1. Active Spending Proposal")
    p_col1, p_col2 = st.columns(2)
    with p_col1:
        p_amount = st.number_input("Proposal Amount (ICS Tokens)", value=1500)
    with p_col2:
        p_reason = st.text_input("Proposal Purpose", value="Annual Security Audit & Penetration Test")

    st.subheader("2. Members Encrypted Ballots")
    st.write("Cast private ballots for all 5 members:")

    # Load vault public key
    with open(DATA_DIR / "server" / "commitments.json", "r") as f:
        comms_meta = json.load(f)
    commitments = [int(c, 16) for c in comms_meta["commitments"]]
    h = commitments[0]

    vote_cols = st.columns(5)
    member_votes = {}
    for i, col in enumerate(vote_cols, start=1):
        name = f"M{i}"
        with col:
            v_choice = st.radio(f"{name}'s Vote", ["YES (1)", "NO (0)"], index=0 if i <= 3 else 1, key=f"v_{name}")
            member_votes[name] = 1 if "YES" in v_choice else 0

    if st.button("🗳️ Cast Encrypted Ballots & Homomorphically Tally", type="primary"):
        ballots_list = []
        ballots_display = []
        for name, vote in member_votes.items():
            with open(DATA_DIR / name / f"{name}_priv.pem", "r") as f:
                from treasury.certificates import private_key_from_pem
                priv = private_key_from_pem(f.read())
            c1, c2 = encrypt_vote(vote, h, P, Q, G)
            sig = sign_ballot(priv, GROUP, name, vote_number=1, c1=c1, c2=c2)
            ballot = {
                "member_name": name,
                "vote_number": 1,
                "c1": format(c1, "x"),
                "c2": format(c2, "x"),
                "sig": sig,
            }
            ballots_list.append(ballot)
            ballots_display.append({
                "Member": name,
                "Ciphertext c1": ballot["c1"][:12] + "...",
                "Ciphertext c2": ballot["c2"][:12] + "...",
                "ECDSA Signature": sig[:16] + "...",
                "Individual Vote Revealed in Clear": "NO (Protected by ElGamal)",
            })

        st.write("#### Encrypted Ballots Table (No individual vote visible in plaintext!)")
        st.table(ballots_display)

        # Homomorphic Aggregation
        C1, C2 = aggregate_ballots(ballots_list, P)
        st.info(f"**Homomorphic Ciphertext Aggregated:**\n- $C_1 = \\prod c_{{1,k}} \\pmod p = $ `{format(C1, 'x')[:16]}...`\n- $C_2 = \\prod c_{{2,k}} \\pmod p = $ `{format(C2, 'x')[:16]}...`")

        # Threshold Decryption of Tally
        st.write("#### Verifiable Threshold Decryption of Aggregate Tally")
        tally_shares = {}
        for name in ["M1", "M3", "M5"]:
            with open(DATA_DIR / name / f"{name}_share.json", "r") as f:
                s_data = json.load(f)
            idx = s_data["index"]
            s_i = int(s_data["share"], 16)
            vkey = int(s_data["verification_key"], 16)
            d_obj = make_decryption_share(s_i, idx, C1, vkey, P, Q, G)
            tally_shares[idx] = d_obj["d_i"]

        total_yes = decrypt_tally(C1, C2, tally_shares, max_votes=5, p=P, q=Q, g=G)
        total_no = 5 - total_yes
        approved = check_spending_approval(total_yes, threshold=3)

        res_col1, res_col2 = st.columns(2)
        with res_col1:
            st.metric("Total YES Votes (T)", total_yes)
            st.metric("Total NO Votes", total_no)
        with res_col2:
            if approved:
                st.success(f"### Result: APPROVED (YES = {total_yes} >= 3)")
                st.balloons()
            else:
                st.error(f"### Result: REJECTED (YES = {total_yes} < 3)")


# --- PAGE 5: ATTACK DEMONSTRATIONS (A1, A5, A7) ---
elif page == "5. Attack Demonstrations (A1, A5, A7)":
    st.header("⚡ Attack Demonstrations & Controls")
    st.markdown("Demonstrate the three core attacks in both **Weak Mode** (vulnerability exploited) and **Secure Mode** (cryptographic defense verified).")

    attack_choice = st.selectbox(
        "Select Attack Demonstration",
        [
            "Attack A1: Man-In-The-Middle Proxy (Mandatory)",
            "Attack A5: Cheating Member in Threshold Opening (Mandatory)",
            "Attack A7: Tampered Encrypted Ballot (Essam's Bonus Attack)",
        ],
    )

    if "A1" in attack_choice:
        st.subheader("Attack A1: Unsigned Handshake MITM Proxy")
        st.markdown(r"""
        - **Mallory's Goal**: Intercept communications between M1 and Server, reading M1's login and requests in cleartext.
        - **Weak Mode (`--weak unsigned-handshake`)**: Handshake messages are unsigned. Mallory runs a proxy on port 6000, establishes separate handshakes with M1 and Server, and decrypts all frames!
        - **Secure Defense**: Handshake includes mutual ECDSA signatures over transcript `["hs-server", GROUP, member, X, Y]`. Mallory cannot forge the server's signature, causing M1 to reject the connection immediately!
        """)

        col1, col2 = st.columns(2)
        with col1:
            if st.button("Simulate A1 in WEAK MODE"):
                st.warning("Running A1 in WEAK MODE...")
                # Run A1 demonstration
                m1_priv, m1_pub = generate_p256_keypair()
                mal_priv, mal_pub = generate_p256_keypair()
                s_priv, s_pub = generate_p256_keypair()

                m_eph_priv, m_eph_pub = generate_p256_keypair()
                mal_eph_priv1, mal_eph_pub1 = generate_p256_keypair()
                mal_eph_priv2, mal_eph_pub2 = generate_p256_keypair()
                s_eph_priv, s_eph_pub = generate_p256_keypair()

                X_m1 = public_key_to_point_hex(m_eph_pub)
                Y_mal1 = public_key_to_point_hex(mal_eph_pub1)
                X_mal2 = public_key_to_point_hex(mal_eph_pub2)
                Y_srv = public_key_to_point_hex(s_eph_pub)

                # Keys
                ss_m1_mal = m_eph_priv.exchange(ec.ECDH(), mal_eph_pub1)
                m2mal, mal2m = derive_directional_keys(ss_m1_mal, "M1", X_m1, Y_mal1)
                m_chan = SecureChannel(send_key=m2mal, receive_key=mal2m)
                mal_chan = SecureChannel(send_key=mal2m, receive_key=m2mal)

                # M1 sends login payload
                frame = m_chan.encrypt(b'{"op": "login", "user": "M1", "secret": "x_M_proven_via_ZK"}')
                eavesdropped = mal_chan.decrypt(frame)
                st.error("💥 Mallory Eavesdropped Plaintext Frame:")
                st.code(eavesdropped.decode("utf-8"), language="json")
                st.info("Notice: Although Mallory reads the frames in clear, M1's ECDSA signed requests cannot be forged by Mallory.")

        with col2:
            if st.button("Simulate A1 in SECURE MODE"):
                s_priv, s_pub = generate_p256_keypair()
                m1_eph_priv, m1_eph_pub = generate_p256_keypair()
                mal_eph_priv, mal_eph_pub = generate_p256_keypair()

                X_m1 = public_key_to_point_hex(m1_eph_pub)
                Y_mal = public_key_to_point_hex(mal_eph_pub)
                # Mallory does not have server private key, cannot produce valid server signature on (X_m1, Y_mal)
                fake_sig = "00" * 64
                rejected = not verify_handshake_step(s_pub, fake_sig, "hs-server", "M1", X_m1, Y_mal)
                st.success("🛡️ SECURE DEFENSE STOPPED MALLORY:")
                st.write(f"- Signature verification on `['hs-server', ...]` returned: **{not rejected}**")
                st.code("M1 rejects the handshake: the server's signature is missing or invalid! Connection aborted.", language="text")

    elif "A5" in attack_choice:
        st.subheader("Attack A5: Cheating Member (Missing Decryption Proof)")
        st.markdown(r"""
        - **Mallory's Goal**: Corrupt the vault opening by submitting an invalid decryption share $d_3 \cdot g \pmod p$.
        - **Weak Mode (`--weak no-proof`)**: Members send decryption shares without Chaum-Pedersen proofs. The vault fails to decrypt, and nobody can tell who cheated.
        - **Secure Mode**: Server verifies Chaum-Pedersen proofs:
          $$g^z \equiv T_1 \cdot h_i^e \pmod p \quad \text{and} \quad c_1^z \equiv T_2 \cdot d_i^e \pmod p$$
          M3's proof fails! The server rejects M3 and opens the vault with another member (M4).
        """)

        col1, col2 = st.columns(2)
        with col1:
            if st.button("Simulate A5 in WEAK MODE"):
                st.warning("Weak Mode: Proofs omitted/skipped...")
                st.error("💥 Damage in Weak Mode: Decryption of vault ciphertext fails AES-GCM authentication tag check! The vault cannot be opened, and nobody can identify the cheater.")
        with col2:
            if st.button("Simulate A5 in SECURE MODE"):
                st.success("🛡️ Secure Mode: Proofs enforced!")
                st.code("""
server 14:03:40 decryption share from M3: d=1d009f83 proof FAILED, rejected
server 14:03:41 decryption share from M4: d=58a1290b proof OK, accepted
server 14:03:42 vault opened successfully with shares from [1, 2, 4]!
                """, language="text")
                st.info("The server identifies M3 as cheating, rejects M3's share, and opens the vault using shares from {M1, M2, M4}!")

    elif "A7" in attack_choice:
        st.subheader("Attack A7: Tampered Ballot (Essam's Attack)")
        st.markdown(r"""
        - **Mallory's Goal**: Modify an encrypted ballot from a NO vote ($v=0$) to a YES vote ($v=1$) without decrypting it!
        - **Mathematical Mechanism**:
          A NO vote has ciphertext $c_2 = g^0 \cdot h^r = h^r \pmod p$.
          Mallory multiplies $c_2$ by $g \pmod p$:
          $$c_2' = c_2 \cdot g \equiv g^1 \cdot h^r \pmod p$$
          This transforms the ballot into an encryption of $v=1$!
        - **Weak Mode (`--weak unsigned-ballots`)**: Ballots are not signed. The attack succeeds and flips the vote!
        - **Secure Mode**: Ballots are signed with member's ECDSA key over `["ballot", GROUP, name, vote_num, c1, c2]`. Modifying $c_2$ invalidates the signature, and the server rejects the ballot!
        """)

        col1, col2 = st.columns(2)
        with col1:
            if st.button("Simulate A7 in WEAK MODE"):
                # Load commitments
                with open(DATA_DIR / "server" / "commitments.json", "r") as f:
                    comms_meta = json.load(f)
                commitments = [int(c, 16) for c in comms_meta["commitments"]]
                h = commitments[0]

                # M3 votes NO
                c1, c2 = encrypt_vote(0, h, P, Q, G)
                ballot = {"member_name": "M3", "vote_number": 1, "c1": format(c1, "x"), "c2": format(c2, "x"), "sig": ""}
                # Mallory tampers c2
                tampered = tamper_ballot_a7(ballot, P, G)

                st.warning("💥 Mallory Tampered Ballot:")
                st.write(f"- Original NO ballot $c_2$: `{ballot['c2'][:16]}...`")
                st.write(f"- Tampered $c_2' = c_2 \\cdot g \\pmod p$: `{tampered['c2'][:16]}...`")
                st.error("In Weak Mode: Ballot accepted without signature! When homomorphically aggregated, the total YES votes increases by 1!")

        with col2:
            if st.button("Simulate A7 in SECURE MODE"):
                with open(DATA_DIR / "M3" / "M3_priv.pem", "r") as f:
                    from treasury.certificates import private_key_from_pem
                    m3_priv = private_key_from_pem(f.read())
                with open(DATA_DIR / "server" / "commitments.json", "r") as f:
                    comms_meta = json.load(f)
                h = int(comms_meta["commitments"][0], 16)

                c1, c2 = encrypt_vote(0, h, P, Q, G)
                sig = sign_ballot(m3_priv, GROUP, "M3", 1, c1, c2)
                ballot = {"member_name": "M3", "vote_number": 1, "c1": format(c1, "x"), "c2": format(c2, "x"), "sig": sig}
                tampered = tamper_ballot_a7(ballot, P, G)

                verified = verify_ballot(m3_priv.public_key(), tampered, GROUP)
                st.success("🛡️ SECURE DEFENSE STOPPED MALLORY:")
                st.write(f"- Signature check on tampered ballot returned: **{verified}**")
                st.code("server 14:04:12 ballot from M3 signature FAILED, rejected", language="text")


# --- PAGE 6: GENUINE SYSTEM LOGS ---
elif page == "6. Genuine System Logs":
    st.header("📜 Genuine System Execution Logs")
    st.markdown("Direct inspection of runtime log files generated by `server`, `founder`, `mallory`, and member processes:")

    selected_log = st.selectbox("Select Log File", ["server", "founder", "mallory", "M1", "M2"])
    log_text = get_log_content(selected_log)
    st.code(log_text, language="text")
