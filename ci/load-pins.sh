# shellcheck shell=bash
# Sourced by the bash harnesses: exports every KEY=value line of ci/pins.env.
# The file is not sourced directly: POLICY_K8S_VERSIONS holds spaces, and
# `source` would run its second word as a command. Each line is exported as
# literal text, never evaluated.
_pins_file="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/pins.env"
if [[ ! -r "$_pins_file" ]]; then
  echo "cannot read $_pins_file" >&2
  return 1
fi
while IFS= read -r _pins_line || [[ -n "$_pins_line" ]]; do
  case "$_pins_line" in '' | '#'*) continue ;; esac
  export "${_pins_line?}"
done <"$_pins_file"
unset _pins_file _pins_line
