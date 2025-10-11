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
