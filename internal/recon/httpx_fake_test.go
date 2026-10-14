package recon

import (
	"strings"
)

// httpxListBody is a fake httpx's script body: for each line of its -l list
// (or its one -u target) it prints the recorded line (the file out) with that line
// as its "input", as httpx -json -probe prints at least one line per input.
// bad.example gets no line (a list of only bad inputs exits 1, like httpx
// with no valid input); slow.example answers after delay seconds, or after
// httpx's -timeout when that is shorter, with a failed line.
func httpxListBody(out, delay string) string {
	s := `list=""; one=""; to=10; prev=""
for a in "$@"; do
  [ "$prev" = "-l" ] && list="$a"
  [ "$prev" = "-u" ] && one="$a"
  [ "$prev" = "-timeout" ] && to="$a"
  prev="$a"
done
if [ -z "$list" ]; then
  [ -n "$one" ] || { echo 'no -l list or -u target' >&2; exit 6; }
  list=$(mktemp); printf '%s\n' "$one" > "$list"
fi
n=0; bad=0
while IFS= read -r t; do
  n=$((n+1))
  case "$t" in
    *bad.example*) bad=$((bad+1));;
    *slow.example*) d=DELAY; [ "$to" -lt "$d" ] && d="$to"; sleep "$d"
      printf '{"input":"%s","url":"%s","failed":true,"error":"context deadline exceeded"}\n' "$t" "$t";;
    *) sed "s#\"input\": \"[^\"]*\"#\"input\": \"$t\"#" OUT;;
  esac
done < "$list"
[ "$bad" -eq "$n" ] && { echo 'no valid input' >&2; exit 1; }
exit 0
`
	return strings.NewReplacer("DELAY", delay, "OUT", out).Replace(s)
}
