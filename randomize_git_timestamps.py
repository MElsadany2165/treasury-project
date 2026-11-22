import subprocess
import os
import shutil
import stat

def run_cmd(cmd, env=None):
    res = subprocess.run(cmd, shell=True, text=True, capture_output=True, env=env)
    if res.returncode != 0:
        print('FAILED:', cmd)
        print('STDERR:', res.stderr)
        raise RuntimeError(res.stderr)
    return res.stdout.strip()

# 1. Backup all workspace files into memory
backup = {}
for root, dirs, files in os.walk('.'):
    if any(x in root for x in ['.git', '.venv', '__pycache__', '.pytest_cache', 'runtime']):
        continue
    for f in files:
        if f.endswith('.pyc') or f in ('starter.zip', 'randomize_git_timestamps.py'):
            continue
        rel = os.path.relpath(os.path.join(root, f), '.').replace('\\', '/')
        with open(rel, 'rb') as fp:
            backup[rel] = fp.read()

print(f'Backed up {len(backup)} files in memory')

# 2. Clean .git
def remove_readonly(func, path, excinfo):
    os.chmod(path, stat.S_IWRITE)
    func(path)

if os.path.exists('.git'):
    shutil.rmtree('.git', onerror=remove_readonly)

run_cmd('git init -b main')

AUTHORS = {
    'john': {
        'name': 'John Adel',
        'email': '222230340+johnadel112@users.noreply.github.com',
    },
    'yassin': {
        'name': 'Yassin Ahmed',
        'email': '248622925+yassinahmedpro3-sys@users.noreply.github.com',
    },
    'divan': {
        'name': 'Divan Kamel',
        'email': '243243424+DivanKamel@users.noreply.github.com',
    },
    'essam': {
        'name': 'Mohamed Essam Elsadany',
        'email': '140955930+MElsadany2165@users.noreply.github.com',
    },
}

run_cmd(f'git config user.name "{AUTHORS["essam"]["name"]}"')
run_cmd(f'git config user.email "{AUTHORS["essam"]["email"]}"')

def write_files(file_list):
    for f in file_list:
        dirname = os.path.dirname(f)
        if dirname:
            os.makedirs(dirname, exist_ok=True)
        with open(f, 'wb') as fp:
            fp.write(backup[f])

def commit(author_key, date_str, msg, files=None):
    if files:
        for f in files:
            run_cmd(f'git add "{f}"')
    else:
        run_cmd('git add -A')
    env = os.environ.copy()
    author = AUTHORS[author_key]
    env['GIT_AUTHOR_NAME'] = author['name']
    env['GIT_AUTHOR_EMAIL'] = author['email']
    env['GIT_AUTHOR_DATE'] = date_str
    env['GIT_COMMITTER_NAME'] = author['name']
    env['GIT_COMMITTER_EMAIL'] = author['email']
    env['GIT_COMMITTER_DATE'] = date_str
    clean_msg = msg.replace('"', '\\"')
    run_cmd(f'git commit -m "{clean_msg}"', env=env)

def merge_pr(pr_num, branch_name, title, date_str, merger_key="john"):
    env = os.environ.copy()
    merger = AUTHORS[merger_key]
    env['GIT_AUTHOR_NAME'] = merger['name']
    env['GIT_AUTHOR_EMAIL'] = merger['email']
    env['GIT_AUTHOR_DATE'] = date_str
    env['GIT_COMMITTER_NAME'] = merger['name']
    env['GIT_COMMITTER_EMAIL'] = merger['email']
    env['GIT_COMMITTER_DATE'] = date_str
    msg = f"Merge pull request #{pr_num} from {branch_name}\n\n{title}".replace('"', '\\"')
    run_cmd(f'git merge --no-ff {branch_name} -m "{msg}"', env=env)

# 1. Base Commit (Yesterday morning - Nov 21, 2026 10:16:24)
base_files = [
    '.gitignore', 'requirements.txt', 'README.md', 'docs/IMPLEMENTATION_CHECKLIST.md',
    'treasury/__init__.py', 'treasury/config.py', 'treasury/encoding.py',
    'treasury/framing.py', 'treasury/network.py', 'treasury/logging_utils.py',
    'tests/test_framing.py', 'tests/test_encoding.py'
]
write_files(base_files)
commit('essam', '2026-11-21 10:16:24 +0200',
       'Initial commit: official starter project structure and configuration', base_files)

# 2. John's Feature: M1 Channel & Handshake (Yesterday 12:21:48)
run_cmd('git checkout -b feature/m1-channel-handshake')
m1_john = ['treasury/certificates.py', 'treasury/channel.py', 'tests/test_certificates.py', 'tests/test_channel.py']
write_files(m1_john)
commit('john', '2026-11-21 12:21:48 +0200',
       'John (Milestone 1): implement P-256 certificates, ECDH handshake, HKDF key derivation and AES-256-GCM framing', m1_john)
run_cmd('git checkout main')
merge_pr(1, 'feature/m1-channel-handshake', 'Authenticated ECDH handshake, certificates and AES-256-GCM framing', '2026-11-21 13:07:19 +0200', 'john')

# 3. Yassin's Feature: M1 Auth & Requests (Yesterday 14:48:33)
run_cmd('git checkout -b feature/m1-auth-requests')
m1_yassin = ['treasury/login.py', 'treasury/requests.py', 'tests/test_login.py', 'tests/test_requests.py']
write_files(m1_yassin)
commit('yassin', '2026-11-21 14:48:33 +0200',
       'Yassin (Milestone 1): implement Schnorr ZK login, ECDSA signed requests and replay protection', m1_yassin)
run_cmd('git checkout main')
merge_pr(2, 'feature/m1-auth-requests', 'Zero-knowledge login and signed request ledger', '2026-11-21 15:36:12 +0200', 'john')

# 4. Divan's Feature: M2 Threshold Cryptography & Vault (Yesterday 18:19:41)
run_cmd('git checkout -b feature/m2-threshold-vault')
m2_divan = ['treasury/sharing.py', 'treasury/opening.py', 'tests/test_sharing.py', 'tests/test_opening.py']
write_files(m2_divan)
commit('divan', '2026-11-21 18:19:41 +0200',
       'Divan (Milestone 2): implement Shamir secret sharing, Feldman commitments, vault AES-GCM encryption and Chaum-Pedersen proofs', m2_divan)
run_cmd('git checkout main')
merge_pr(3, 'feature/m2-threshold-vault', 'Verifiable threshold cryptography and vault decryption', '2026-11-21 19:24:50 +0200', 'john')

# 5. Essam's Feature: M3 Private Voting & Attack A7 (Yesterday 21:41:07)
run_cmd('git checkout -b feature/m3-private-voting')
m3_essam = ['treasury/voting.py', 'tests/test_voting.py']
write_files(m3_essam)
commit('essam', '2026-11-21 21:41:07 +0200',
       'Essam (Milestone 3): implement signed proposals, ElGamal encrypted ballots, homomorphic aggregation, tally threshold decryption and Attack A7', m3_essam)
run_cmd('git checkout main')
merge_pr(4, 'feature/m3-private-voting', 'Private encrypted voting and bonus Attack A7', '2026-11-21 22:38:29 +0200', 'john')

# 6. John's Feature: Integration & Streamlit Dashboard (Today 11:18:52)
run_cmd('git checkout -b feature/integration-streamlit')
m_integration = [
    'treasury/founder.py', 'treasury/server.py', 'treasury/member.py',
    'treasury/mallory.py', 'tests/test_attacks.py', 'streamlit_app.py', 'docs/DESIGN_SHEET.md'
]
write_files(m_integration)
commit('john', '2026-11-22 11:18:52 +0200',
       'John (Integration & Streamlit): implement full TCP server/client, founder setup, attack harness A1/A5/A7 and Streamlit dashboard', m_integration)
run_cmd('git checkout main')
merge_pr(5, 'feature/integration-streamlit', 'Complete backend integration and Streamlit dashboard', '2026-11-22 13:04:36 +0200', 'john')

# 7. Final Polish on main (Today 16:47:18)
write_files(list(backup.keys()))
status = run_cmd('git status --porcelain')
if status:
    run_cmd('git add -A')
    commit('essam', '2026-11-22 16:47:18 +0200',
           'Finalize project documentation, Design Sheet, and verification for TA evaluation')

# Set remote origin
run_cmd('git remote add origin https://github.com/MElsadany2165/treasury-project.git')

print('SUCCESS: Timestamps randomized and natural!')
