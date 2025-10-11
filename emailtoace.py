#!/usr/bin/env python3
"""
email_to_ace.py

Compute ACE (Punycode / IDNA) for an input email or domain.

Usage examples:
  # domain
  python email_to_ace.py "gmáil.com"

  # email (will punycode the domain part only)
  python email_to_ace.py "security@gmáil.com"

  # make local-part ASCII-safe too (strip diacritics + replace non-ascii)
  python email_to_ace.py "ṡecurity@gmáil.com" --ascii-local

  # decode ACE domain back to unicode
  python email_to_ace.py "xn--gml-6na.com" --decode

  # show codepoints (helpful to debug which accent/codepoint you used)
  python email_to_ace.py "gma\u0301il.com" --show-codepoints

Dependency:
  pip install idna
"""

from __future__ import annotations
import argparse
import unicodedata
import re
import sys
from typing import Tuple

try:
    import idna
except Exception:
    sys.exit("Missing dependency: run 'pip install idna'")

def normalize_nfc(s: str) -> str:
    return unicodedata.normalize("NFC", s)

def show_codepoints(s: str) -> str:
    return " ".join(f"U+{ord(c):04X}" for c in s)

def ascii_safe_local(local: str) -> str:
    # Remove diacritics, replace non-ascii with underscore, and collapse invalid chars
    nf = normalize_nfc(local)
    stripped = "".join(ch for ch in nf if not unicodedata.combining(ch))
    safe = re.sub(r"[^\x00-\x7f]", "_", stripped)
    safe = re.sub(r"[^A-Za-z0-9._%+\-]", "_", safe)
    return safe or "user"

def encode_domain_to_ace(domain: str) -> str:
    domain_nfc = normalize_nfc(domain)
    ace = idna.encode(domain_nfc).decode()
    return ace

def decode_ace_to_unicode(ace_domain: str) -> str:
    return idna.decode(ace_domain)

def split_email_or_domain(inp: str) -> Tuple[str, str]:
    if "@" in inp:
        local, domain = inp.split("@", 1)
        return local, domain
    else:
        return "", inp

def main():
    p = argparse.ArgumentParser(description="Convert email or domain to ACE (Punycode) and inspect codepoints.")
    p.add_argument("input", help="Email (local@domain) or domain (e.g. gmáil.com)")
    p.add_argument("--ascii-local", action="store_true",
                   help="Make the local-part ASCII-safe (strip diacritics + replace non-ASCII).")
    p.add_argument("--decode", action="store_true",
                   help="If input is ACE domain (xn--...), decode back to Unicode and print.")
    p.add_argument("--show-codepoints", action="store_true",
                   help="Show Unicode codepoints for the input parts (useful for debugging).")
    args = p.parse_args()

    inp = args.input.strip()

    if args.decode:
        # decode ACE (domain or email domain)
        if "@" in inp:
            local, domain = split_email_or_domain(inp)
            try:
                decoded = decode_ace_to_unicode(domain)
                print(f"Decoded: {local}@{decoded}")
            except Exception as e:
                print(f"IDNA decode error for domain {domain!r}: {e}")
        else:
            try:
                print(f"Decoded: {decode_ace_to_unicode(inp)}")
            except Exception as e:
                print(f"IDNA decode error for {inp!r}: {e}")
        return

    local, domain = split_email_or_domain(inp)

    if args.show_codepoints:
        if local:
            print("Local-part codepoints:")
            print(" ", show_codepoints(local))
        print("Domain (raw) codepoints:")
        print(" ", show_codepoints(domain))
        print("----")

    # Normalize and encode domain
    domain_nfc = normalize_nfc(domain)
    try:
        ace = encode_domain_to_ace(domain_nfc)
    except Exception as e:
        print(f"ERROR: IDNA encode failed for domain {domain!r}: {e}")
        sys.exit(2)

    # Optionally make local ascii safe
    out_local = local
    if local and args.ascii_local:
        out_local = ascii_safe_local(local)

    # Print results
    if local:
        print(f"Input email:        {inp}")
        print(f"Local-part (NFC):   {normalize_nfc(local)}")
        if args.show_codepoints:
            print("  local-part codepoints:", show_codepoints(normalize_nfc(local)))
        print(f"Domain (NFC):       {domain_nfc}")
        if args.show_codepoints:
            print("  domain codepoints: ", show_codepoints(domain_nfc))
        print(f"ACE domain:         {ace}")
        print()
        print("Ready-to-use forms:")
        print(f"  Unicode email (raw): {local}@{domain_nfc}")
        print(f"  ACE email (mailbox): {out_local}@{ace}")
        if args.ascii_local and local != out_local:
            print(f"  Note: ascii-local used -> {out_local}@{ace}")
    else:
        # domain only
        print(f"Input domain: {domain}")
        print(f"Domain (NFC): {domain_nfc}")
        if args.show_codepoints:
            print("  domain codepoints: ", show_codepoints(domain_nfc))
        print(f"ACE domain:   {ace}")

    print("\nNotes:")
    print(" - IDNA/Punycode applies to domain labels (right of @).")
    print(" - For PoC / mail deliverability: prefer ASCII local-parts and punycode the domain (ACE).")
    print(" - Always normalize input to NFC before encoding (this script does that).")
    print(" - If you see unexpected ACEs, check codepoints (--show-codepoints) to diagnose grave vs acute vs combining marks.")

if __name__ == "__main__":
    main()

