Punycode‑IDN‑ATO — 0 click account takeover POC lab and tools

Quick project description

This repo contains:

app.py — intentionally vulnerable Flask application that demonstrates inconsistent email normalization leading to ATO. (Signup stores raw email; password‑reset performs diacritic‑stripping normalization.)

punycode_converter.py — small CLI script to generate Punycode and common homoglyph substitutions for a given input (useful to craft PoCs).

Docker / MailHog compose — one‑command lab setup for reproducible demos.

Getting started — prerequisites

Python 3.8+

Docker & docker‑compose (recommended, for MailHog)

(Optional) Burp Suite Community for intercepting and editing requests

Install & run locally (recommended)

Clone & start:

git clone https://github.com/yourname/punycode-idn-ato.git
cd punycode-idn-ato

# create venv (optional)
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# start MailHog + app using docker-compose
docker-compose up --build


App: http://127.0.0.1:5000

MailHog UI: http://localhost:8025

If you prefer running without Docker:

# ensure MailHog or another SMTP sink is running at localhost:1025
pip install -r requirements.txt
python app.py

punycode_converter.py — usage

A tiny CLI to generate Punycode (ACE) and simple homoglyph variants. Save as punycode_converter.py.

Example script (included in repo):

#!/usr/bin/env python3
# punycode_converter.py
import sys
import argparse
import idna

HOMOGLYPHS = {
    'a': ['а', 'à', 'á', 'â', 'ä'],   # Cyrillic a, Latin accents
    'e': ['е', 'è', 'é', 'ê', 'ë'],
    'o': ['о', 'ò', 'ó', 'ô', 'ö'],
    # add more as needed
}

def to_punycode(domain):
    # domain can be a full email or hostname; we'll punycode the domain part
    parts = domain.split('@')
    if len(parts) == 2:
        local, host = parts
    else:
        local, host = '', parts[0]
    try:
        ace = idna.encode(host).decode()
    except Exception as e:
        ace = f"ERROR: {e}"
    return (local, host, ace)

def homoglyphs_for(word, max_results=10):
    out = set()
    out.add(word)
    for i, ch in enumerate(word):
        if ch.lower() in HOMOGLYPHS:
            for sub in HOMOGLYPHS[ch.lower()]:
                candidate = word[:i] + sub + word[i+1:]
                out.add(candidate)
                if len(out) >= max_results:
                    return list(out)
    return list(out)

if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("input", help="email or hostname or local-part@domain")
    args = p.parse_args()
    local, host, ace = to_punycode(args.input)
    print("Input:", args.input)
    if local:
        print("Local-part:", local)
    print("Domain (unicode):", host)
    print("Domain (ACE / punycode):", ace)
    print()
    # show some homoglyph examples for the local or the domain (simple)
    target = local if local else host
    print("Some homoglyph variants (sample):")
    for v in homoglyphs_for(target, max_results=12):
        if local:
            print(f"  {v}@{host}")
        else:
            print(f"  {v}")


Install dependency:

pip install idna


Run examples:

python punycode_converter.py "security@gmail.com"
python punycode_converter.py "example.com"


This prints ACE (punycode) for domain parts, and generates quick homoglyph subs you can test in the lab.

PoC (exact minimal reproduction)

Start app & MailHog.

Signup victim: security@gmail.com / Passw0rd!

Signup attacker: security@gmáil.com (accent on a) / any password.

Use the app’s Forgot Password and submit security@gmail.com.

Open MailHog → copy reset link sent to the stored attacker address.

Reset password and login as security@gmail.com with the new password.

Tip: use Burp Proxy to intercept and ensure the raw Unicode or ACE is delivered to the app (browsers sometimes auto-encode).

Docker / docker-compose

Sample docker-compose.yml included:

version: '3.8'
services:
  app:
    build: .
    ports:
      - "5000:5000"
    environment:
      - SMTP_HOST=mailhog
      - SMTP_PORT=1025
      - BASE_URL=http://localhost:5000
    depends_on:
      - mailhog

  mailhog:
    image: mailhog/mailhog
    ports:
      - "8025:8025"
      - "1025:1025"


Sample Dockerfile (simple):

FROM python:3.11-slim
WORKDIR /app
COPY . /app
RUN pip install -r requirements.txt
EXPOSE 5000
CMD ["python", "app.py"]

What to change for a real bug bounty test (short)

Replace MailHog with a mailbox/domain you control (create DNS MX records & catch‑all mailbox). MailHog cannot receive external mail.

Use Interactsh if the target performs DNS/HTTP OOB callbacks rather than SMTP.

Avoid disposable inboxes unless allowed — use your domain or allowed provider.

Keep evidence minimal and non‑destructive: request/response pairs, reset email headers, timestamps, and final login confirmation.

Cleanup & safety

This app is intentionally vulnerable: run locally or on isolated infrastructure only.

To cleanup after running with Docker:

docker-compose down
docker rm -f mailhog || true
rm users.db || true


Never test against third‑party services without explicit permission.

Contribution & license

PRs welcome for additional homoglyph lists, better converter options, or test cases.

Suggested license: MIT — include LICENSE file if you publish.

Disclosure & disclaimer (must read)

This repository is for authorized security research, education, and lab demonstration only. Do not use these techniques on systems you do not own or do not have permission to test. Misuse could be illegal and unethical. Always follow applicable laws and bug bounty program rules.
