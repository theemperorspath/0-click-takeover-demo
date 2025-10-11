#!/usr/bin/env python3
"""
Generate prioritized punycode (ACE) variants for a single domain label.

Usage:
  python gen_puny_variants.py gmail
"""
import sys
import unicodedata
import itertools
import idna

# small, practical homoglyph map (expand as needed)
HOMO = {
    'a': ['á','à','â','ä','а'],    # last is Cyrillic U+0430
    'e': ['é','è','ë','е'],        # includes Cyrillic
    'i': ['í','ì','ï','ι'],        # greek iota 'ι' sometimes
    'o': ['ó','ò','ö','о'],        # Cyrillic 'о'
    's': ['ś','š','ѕ'],            # Cyrillic 'ѕ'
    'g': ['ɡ'],                    # Latin small script g (less common)
    'm': ['м'],                    # Cyrillic 'м'
    'l': ['ł','ⅼ'],                # etc
    # add other mappings as needed
}

MAX_SUBS = 2   # max number of simultaneous substitutions (keeps the set small)

def normalize_nfc(s):
    return unicodedata.normalize('NFC', s)

def gen_variants(label, max_subs=MAX_SUBS):
    label = label
    positions = list(range(len(label)))
    variants = set()
    # zero-sub (original)
    variants.add(label)
    # for 1..max_subs substitutions
    for k in range(1, max_subs+1):
        for pos_combo in itertools.combinations(positions, k):
            # for each chosen pos, pick a replacement (or skip if none)
            choices = []
            skip_combo = False
            for pos in pos_combo:
                ch = label[pos].lower()
                if ch in HOMO:
                    choices.append(HOMO[ch])
                else:
                    skip_combo = True
                    break
            if skip_combo:
                continue
            # product of replacements
            for repls in itertools.product(*choices):
                lab_list = list(label)
                for i,pos in enumerate(pos_combo):
                    lab_list[pos] = repls[i]
                candidate = ''.join(lab_list)
                variants.add(candidate)
    return variants

def to_ace(label, tld='com'):
    dom = f"{label}.{tld}"
    dom_nfc = normalize_nfc(dom)
    try:
        ace = idna.encode(dom_nfc).decode()
        return ace
    except Exception as e:
        return None

def main():
    if len(sys.argv) < 2:
        print("Usage: gen_puny_variants.py <label> [tld]")
        sys.exit(1)
    label = sys.argv[1]
    tld = sys.argv[2] if len(sys.argv) > 2 else 'com'
    variants = gen_variants(label)
    results = {}
    for v in sorted(variants):
        ace = to_ace(v, tld=tld)
        if ace:
            results[ace] = v
    # print unique ACEs with the original unicode label that produced it
    for ace,orig in results.items():
        print(f"{orig} -> {ace}")

if __name__ == '__main__':
    main()
