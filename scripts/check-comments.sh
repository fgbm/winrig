#!/usr/bin/env bash
# Fails on comments that restate the code, refer to review history, narrate steps,
# or are not in English. The rules are in AGENTS.md, section 10.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

# The directories to scan. A positional argument or COMMENT_CHECK_DIRS overrides
# the default; the self-test points this at the fixture directories.
if [ "$#" -gt 0 ]; then
  dirs=("$@")
else
  read -r -a dirs <<<"${COMMENT_CHECK_DIRS:-src tests}"
fi

if ! command -v rg >/dev/null 2>&1; then
  echo "check-comments: ripgrep (rg) is not installed" >&2
  exit 2
fi

findings=0

# rg exits 1 when it finds nothing.
scan() {
  local pattern="$1"
  shift
  rg -n --no-heading --with-filename -g '*.rs' -e "$pattern" "$@" || true
}

# Prints each finding with its rule and counts it. A trailing
# `// comment-check: allow` skips the line.
emit() {
  local rule="$1"
  local line
  while IFS= read -r line; do
    [ -n "$line" ] || continue
    case "$line" in
      *'comment-check: allow'*) continue ;;
    esac
    printf '%s  [rule: %s]\n' "$line" "$rule"
    findings=$((findings + 1))
  done
}

# A short restatement of the code, such as "The user." or "Creates a tenant.".
restatement='^\s*//[/!]?\s*(The|A|An|Returns?|Creates?|Gets?|Sets?|Checks?|Builds?|Reads?|Writes?)\b[^.]{0,40}\.$'
# A reference to a review finding, an issue or a change slice. A winrig ID such as
# DR-4 or ADR-0009 has a letter then a hyphen, so the letter-then-digit rule does not
# match it and such a reference stays permitted.
review_id='^\s*//.*\b[NDMHL][0-9]+\b'
review_text='^\s*//.*(per (the )?review|review finding|issue #[0-9]+)'
slice_id='^\s*//.*\bW[0-9]+\b'
# A comment that narrates a step.
narration='^\s*//\s*(Now|Then|First|Next|Finally|Step [0-9])\b'
# Boilerplate that names the code item instead of the contract.
boilerplate='^\s*//[/!]?\s*The function (returns|selects|takes|checks)\b'
# A comment that is not in English (ADR-0016).
cyrillic='^\s*//.*[А-Яа-яЁё]'

emit restatement < <(scan "$restatement" "${dirs[@]}")
emit review-reference < <(scan "$review_id" "${dirs[@]}")
emit review-reference < <(scan "$review_text" "${dirs[@]}")
emit review-reference < <(scan "$slice_id" "${dirs[@]}")
emit narration < <(scan "$narration" "${dirs[@]}")
emit boilerplate < <(scan "$boilerplate" "${dirs[@]}")
emit cyrillic-not-english < <(scan "$cyrillic" "${dirs[@]}")

# The doc-comment rules need the item that the block documents, so they run in awk.
# Rule 1: the first sentence of a doc block restates the item name.
# Rule 2: three or more sentences of one doc block start with the same subject.
while IFS= read -r file; do
  [ -n "$file" ] || continue
  awk_findings="$(
    awk '
      function clean(w) { gsub(/[^A-Za-z0-9_]/, "", w); return w }
      function stem(w,   n) {
        w = tolower(w); n = length(w)
        if (n > 4 && w ~ /ing$/) return substr(w, 1, n - 3)
        if (n > 3 && w ~ /ed$/)  return substr(w, 1, n - 2)
        if (n > 3 && w ~ /es$/)  return substr(w, 1, n - 2)
        if (n > 2 && w ~ /s$/)   return substr(w, 1, n - 1)
        return w
      }
      function is_item(line,   rest, name) {
        if (line ~ /^[ \t]*(pub(\([^)]*\))?[ \t]+)?(async[ \t]+)?(unsafe[ \t]+)?(fn|struct|enum|const|type|trait|mod|union)[ \t]+[A-Za-z_]/) {
          rest = line
          sub(/^[ \t]*(pub(\([^)]*\))?[ \t]+)?(async[ \t]+)?(unsafe[ \t]+)?(fn|struct|enum|const|type|trait|mod|union)[ \t]+/, "", rest)
          sub(/[^A-Za-z0-9_].*$/, "", rest)
          return rest
        }
        if (line ~ /^[ \t]*(pub(\([^)]*\))?[ \t]+)?[A-Za-z_][A-Za-z0-9_]*[ \t]*:/) {
          rest = line
          sub(/^[ \t]*(pub(\([^)]*\))?[ \t]+)?/, "", rest)
          sub(/[ \t]*:.*$/, "", rest)
          return rest
        }
        return ""
      }
      { line[NR] = $0 }
      END {
        n = NR; i = 1
        while (i <= n) {
          if (line[i] !~ /^[ \t]*\/\/\//) { i++; continue }
          start = i
          while (i <= n && line[i] ~ /^[ \t]*\/\/\//) i++
          bend = i - 1
          allowed = 0
          text = ""
          for (k = start; k <= bend; k++) {
            if (line[k] ~ /comment-check: allow/) allowed = 1
            t = line[k]
            sub(/^[ \t]*\/\/\//, "", t); sub(/^ /, "", t)
            if (t != "") text = (text == "" ? t : text " " t)
          }
          if (allowed) continue
          # Skip the attribute lines between the doc block and the item. An item with
          # a user-facing attribute carries its contract in that attribute, so its doc
          # comment is not measured against the item name.
          j = i; skip_name = 0
          while (j <= n && line[j] ~ /^[ \t]*#\[/) {
            depth = 0
            do {
              if (line[j] ~ /#\[(tool|schemars|arg)\(/) skip_name = 1
              tmp = line[j]
              depth += gsub(/\[/, "[", tmp)
              depth -= gsub(/\]/, "]", tmp)
              j++
            } while (j <= n && depth > 0)
          }
          itemline = (j <= n) ? line[j] : ""
          # Rule 1.
          if (!skip_name) {
            name = is_item(itemline)
            if (name != "") {
              s = text
              p = index(s, ".")
              s = (p > 0) ? substr(s, 1, p - 1) : ""
              if (s != "") {
                nw = split(s, sw, /[ \t]+/)
                if (nw <= 10) {
                  for (k = 1; k <= nw; k++) sw[k] = stem(clean(sw[k]))
                  nm = name
                  gsub(/([a-z0-9])([A-Z])/, "\\1_\\2", nm)
                  cnt = split(nm, np, "_")
                  all = (cnt > 0)
                  for (k = 1; k <= cnt; k++) {
                    w = stem(clean(np[k]))
                    if (w == "") continue
                    hit = 0
                    for (m = 1; m <= nw; m++) if (sw[m] == w) { hit = 1; break }
                    if (!hit) { all = 0; break }
                  }
                  if (all) print FILENAME ":" start ": doc first sentence restates the item name  [rule: doc-name]"
                }
              }
            }
          }
          # Rule 2.
          c_caller = 0; c_function = 0; c_server = 0
          rest = text
          while (rest != "") {
            p = index(rest, ".")
            if (p == 0) { sent = rest; rest = "" }
            else { sent = substr(rest, 1, p - 1); rest = substr(rest, p + 1) }
            sent = clean(sent)
            if (sent ~ /^Thecaller/) c_caller++
            else if (sent ~ /^Thefunction/) c_function++
            else if (sent ~ /^Theserver/) c_server++
          }
          if (c_caller >= 3 || c_function >= 3 || c_server >= 3)
            print FILENAME ":" start ": doc block repeats the same subject  [rule: doc-subject]"
        }
      }
    ' "$file"
  )"
  if [ -n "$awk_findings" ]; then
    printf '%s\n' "$awk_findings"
    findings=$((findings + $(printf '%s\n' "$awk_findings" | wc -l)))
  fi
done < <(rg --files -g '*.rs' "${dirs[@]}")

# A trailing comment after code on the same line (`code; // text`) carries the
# same Cyrillic and review-reference bans. awk finds the comment outside a
# double-quoted string; rg then matches the comment text, because the Cyrillic
# range needs a UTF-8-aware engine. A `//` inside a string ("http://") and a
# comment-only line (no code before the slashes) are skipped.
trailing_comments="$(
  while IFS= read -r file; do
    [ -n "$file" ] || continue
    awk '
      {
        s = $0
        if (s ~ /comment-check: allow/) next
        n = length(s)
        instr = 0; has_code = 0; pos = 0
        for (i = 1; i < n; i++) {
          c = substr(s, i, 1)
          if (c == "\\" && instr) { i++; continue }
          if (c == "\"") { instr = 1 - instr; continue }
          if (instr) continue
          if (c == "/" && substr(s, i + 1, 1) == "/" && has_code && (substr(s, i - 1, 1) == " " || substr(s, i - 1, 1) == "\t")) { pos = i; break }
          if (c != " " && c != "\t") has_code = 1
        }
        if (pos) print FILENAME ":" FNR ":" substr(s, pos)
      }
    ' "$file"
  done < <(rg --files -g '*.rs' "${dirs[@]}")
)"

if [ -n "$trailing_comments" ]; then
  emit cyrillic-not-english < <(printf '%s\n' "$trailing_comments" | rg -N -e '[А-Яа-яЁё]' || true)
  emit review-reference < <(printf '%s\n' "$trailing_comments" | rg -N -e '\b[NDMHL][0-9]+\b' -e 'per (the )?review' -e 'review finding' -e 'issue #[0-9]+' -e '\bW[0-9]+\b' || true)
fi

# The allow markers stay visible: each one is a deliberate exception.
allow_markers="$(rg --no-heading -o -g '*.rs' -e 'comment-check: allow' "${dirs[@]}" 2>/dev/null | wc -l | tr -d ' ' || true)"

if [ "$findings" -gt 0 ]; then
  echo "check-comments: $findings finding(s)" >&2
  echo "check-comments: $allow_markers allow marker(s)" >&2
  exit 1
fi

echo "check-comments: no findings in ${dirs[*]}"
echo "check-comments: $allow_markers allow marker(s)"
