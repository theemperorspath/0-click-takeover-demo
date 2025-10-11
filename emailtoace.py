#!/usr/bin/env python3
"""
emailtoace.py — robust converter: email/domain/label -> ACE (xn--...), lab-safe.

Usage examples:
  python emailtoace.py "security@gm𝘼il.com"
  python emailtoace.py "gm𝘼il.com"
  python emailtoace.py "gm𝘼il" --tld com
  python emailtoace.py "𝘼" --label-only         # single glyph -> ace for label
  python emailtoace.py "security@gm𝘼il.com" --ascii-local
  python emailtoace.py --batch list.txt         # file with one candidate per line

Notes:
 - This script only helps produce ACE domains for domains/labels you control.
 - It will not register domains for you.
 - Use responsibly and only on domains you own or in lab environments.
"""
from __future__ import annotations
import argparse, sys, unicodedata, re
from typing import Tuple, List

try:
    import idna
except Exception:
    sys.exit("Missing dependency: pip install idna")

# Focused homoglyph suggestions for domain-label usage (expand as needed)
SUGGESTED_SUBS = {
    'a': ['á','à','â','ä','а'],   # Cyrillic a (U+0430) last
    'e': ['é','è','ê','е'],
    'i': ['í','ì','ï','ι'],
    'o': ['ó','ò','ô','ö','о'],
    's': ['ś','š','ѕ'],
    'm': ['м'],
    'g': ['ɡ'],
    'l': ['ł','ⅼ'],
}

def normalize_nfkc_then_nfc(s: str) -> str:
    """Try compatibility folding then canonical composition."""
    nfkc = unicodedata.normalize("NFKC", s)
    return unicodedata.normalize("NFC", nfkc)

def show_codepoints(s: str) -> str:
    return " ".join(f"U+{ord(c):04X}" for c in s)

def split_input(inp: str) -> Tuple[str,str,bool]:
    """
    Returns (local, domain, label_only_flag)
    - if input is an email, returns local, domain
    - if input is domain-only, returns "", domain
    - if label_only flag True, domain is label (no dots)
    """
    inp = inp.strip()
    if "@" in inp:
        local, domain = inp.split("@",1)
        return local, domain, False
    # treat single-token without dot as label-only
    if "." not in inp:
        return "", inp, True
    return "", inp, False

def try_idna_encode(domain: str):
    """Try to idna.encode a full domain like 'label.tld' after normalization."""
    dom_norm = normalize_nfkc_then_nfc(domain)
    try:
        ace = idna.encode(dom_norm).decode()
        return ace, dom_norm
    except Exception as e:
        # if fails, raise with message
        raise RuntimeError(f"IDNA encode failed for '{domain}' (after NFKC/NFC -> '{dom_norm}'): {e}") from e

def suggest_label_variants(label: str, limit: int = 20) -> List[str]:
    """Return a short list of label variants by single-char substitution using SUGGESTED_SUBS."""
    chars = list(label)
    suggestions = []
    for i,ch in enumerate(chars):
        key = ch.lower()
        if key in SUGGESTED_SUBS:
            for sub in SUGGESTED_SUBS[key]:
                cand = ''.join(chars[:i] + [sub] + chars[i+1:])
                suggestions.append(cand)
    # dedupe preserve order
    seen = set(); out=[]
    for s in suggestions:
        if s not in seen:
            out.append(s); seen.add(s)
        if len(out) >= limit:
            break
    return out

def process_candidate(raw_input: str, local_override: str, tld: str, ascii_local: bool, show_cp: bool):
    local, domain_or_label, label_only = split_input(raw_input)

    # If local_override provided via arg, don't override if local exists; only used for label-only input
    if not local and local_override:
        local = local_override

    # Show basic info
    print(f"\nCandidate input: {raw_input}")
    if show_cp:
        print(" Raw codepoints:", show_codepoints(raw_input))

    # If label_only (no dot, no @) treat domain as label+TLD later
    if label_only:
        label = domain_or_label
        domain = f"{label}.{tld}"
        is_label_only = True
    else:
        domain = domain_or_label
        is_label_only = False

    # Normalize / compat-fold domain
    try:
        ace, used_dom = try_idna_encode(domain)
        # success
        print(" Normalized domain used:", used_dom)
        print(" ACE domain:", ace)
        out_local = local or local_override or "user"
        if ascii_local:
            out_local = ascii_localize(out_local)
        if local:
            # present both forms
            print(" Ready emails:")
            print("  Unicode (raw):", f"{local}@{used_dom}")
            print("  ACE (mailbox) :", f"{out_local}@{ace}")
        else:
            print(" Ready domain:", ace)
        return
    except Exception as e:
        print(" ERROR:", e)

    # If encode failed, attempt smarter fallbacks:
    # 1) if domain included an '@' earlier we should not have appended .com; but we split - so this is domain-only issue
    # 2) Try suggestions on label(s) (only substitute characters inside labels)
    print(" Attempting suggestions for domain labels (safe allowed homoglyphs)...")
    labels = domain.split(".")
    tried = 0
    for idx, lab in enumerate(labels):
        variants = suggest_label_variants(lab)
        for v in variants:
            new_labels = labels.copy()
            new_labels[idx] = v
            cand_dom = ".".join(new_labels)
            try:
                ace_v, used_dom_v = try_idna_encode(cand_dom)
                out_local = local or local_override or "user"
                if ascii_local:
                    out_local = ascii_localize(out_local)
                print(f" Suggestion success: {cand_dom} -> {ace_v}")
                print("  Ready email:", f"{out_local}@{ace_v}")
                tried += 1
            except Exception as ex2:
                # suggestion failed, continue
                continue
            if tried >= 6:
                return
    print(" No suggestion produced a valid ACE. Try a different allowed homoglyph (accent/Cyrillic) or register a domain you own.")

def ascii_localize(local: str) -> str:
    # strip diacritics and non-ascii -> underscores
    nf = normalize_nfkc_then_nfc(local)
    stripped = "".join(ch for ch in nf if not unicodedata.combining(ch))
    safe = re.sub(r"[^\x00-\x7f]", "_", stripped)
    safe = re.sub(r"[^A-Za-z0-9._%+\-]", "_", safe)
    return safe or "user"

def batch_process(file_path: str, **kwargs):
    with open(file_path, "r", encoding="utf-8") as f:
        for line in f:
            s = line.strip()
            if not s or s.startswith("#"):
                continue
            process_candidate(s, **kwargs)

def main():
    p = argparse.ArgumentParser(description="Robust email/domain -> ACE (xn--) converter (lab-only).")
    p.add_argument("input", nargs="?", help="Email, domain, label or path to batch file (use --batch for file).")
    p.add_argument("--local", default="security", help="default local-part when input is a label")
    p.add_argument("--tld", default="com", help="TLD to append for bare labels")
    p.add_argument("--ascii-local", action="store_true", help="make local-part ASCII safe for SMTP")
    p.add_argument("--show-codepoints", action="store_true", help="show codepoints for the raw input")
    p.add_argument("--batch", action="store_true", help="treat INPUT as a file path and process each line")
    args = p.parse_args()

    if args.batch:
        if not args.input:
            print("Batch mode requires a file path as INPUT.")
            sys.exit(2)
        batch_process(args.input, local_override=args.local, tld=args.tld, ascii_local=args.ascii_local, show_cp=args.show_codepoints)
        return

    if not args.input:
        p.print_help(); sys.exit(1)

    process_candidate(args.input, local_override=args.local, tld=args.tld, ascii_local=args.ascii_local, show_cp=args.show_codepoints)

if __name__ == "__main__":
    main()
