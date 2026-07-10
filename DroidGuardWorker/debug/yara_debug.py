"""Ad-hoc YARA false-positive triage.

Run your real ruleset against a KNOWN-BENIGN apk (or an extracted apk dir) and
see exactly which rules match and which strings triggered them. Any rule that
lights up here on a clean app is a false-positive source -> downgrade it to
"low" in rule_confidence.json (or drop it).

Usage:
    python yara_debug.py /path/to/rules_dir /path/to/app.apk
    python yara_debug.py /path/to/rules_dir /path/to/extracted_dir/
"""
import os
import sys
import yara


def compile_rules(rules_dir):
    good, rejected = {}, []
    for root, _dirs, files in os.walk(rules_dir):
        for fn in files:
            if fn.endswith((".yar", ".yara")):
                path = os.path.join(root, fn)
                ns = os.path.relpath(path, rules_dir)
                try:
                    yara.compile(filepath=path)
                    good[ns] = path
                except Exception as e:
                    rejected.append((ns, str(e)))
    if rejected:
        print(f"[!] {len(rejected)} rule file(s) failed to compile (skipped):")
        for ns, err in rejected:
            print(f"    - {ns}: {err.splitlines()[0]}")
    return yara.compile(filepaths=good)


def iter_targets(target):
    if os.path.isfile(target):
        yield target
    else:
        for root, _dirs, files in os.walk(target):
            for fn in files:
                yield os.path.join(root, fn)


def main():
    if len(sys.argv) != 3:
        print(__doc__)
        sys.exit(1)
    rules_dir, target = sys.argv[1], sys.argv[2]
    rules = compile_rules(rules_dir)

    hits = {}  # rule_name -> set of (file, matched_string_ids)
    for fp in iter_targets(target):
        try:
            for m in rules.match(fp):
                ids = sorted({s.identifier for s in m.strings})
                hits.setdefault(m.rule, []).append((os.path.basename(fp), ids))
        except Exception as e:
            print(f"[!] scan failed for {fp}: {e}")

    print("\n================ RULES THAT MATCHED ================")
    if not hits:
        print("No rules matched. This target is clean against the ruleset.")
        return
    for rule, occurrences in sorted(hits.items()):
        print(f"\n  RULE: {rule}   ({len(occurrences)} file hit(s))")
        for fname, ids in occurrences[:5]:
            print(f"     - {fname}: strings {ids}")
    print("\n---------------------------------------------------")
    print("Any rule above, matched on a BENIGN app, is a false-positive source.")
    print("Add it to rule_confidence.json overrides as \"low\" (or remove the rule).")

# python debug/yara_debug.py rules extracted
# tar -xf cubeRun.apk -C extracted
if __name__ == "__main__":
    main()