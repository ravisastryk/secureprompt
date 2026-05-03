# scripts/lib/load_env.sh — sourced helper, not run directly.
#
# Loads variables from the repo-root `.env` file into the current shell,
# without overriding values already set in the environment.
#
# Usage:
#   # shellcheck source=lib/load_env.sh
#   source "$(dirname "${BASH_SOURCE[0]}")/lib/load_env.sh"
#   load_env
#
# Format: simple `KEY=VALUE` lines. Blank lines and `#` comments are ignored.
# Values may be optionally wrapped in single or double quotes; quotes are
# stripped. No variable expansion or command substitution is performed.

load_env() {
    local env_file
    env_file="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)/.env"

    if [[ ! -f "${env_file}" ]]; then
        return 0
    fi

    while IFS= read -r raw_line || [[ -n "${raw_line}" ]]; do
        # Strip CR (in case the file came from Windows) and skip blanks/comments.
        local line="${raw_line%$'\r'}"
        case "${line}" in
            ''|\#*) continue ;;
        esac

        # Split on the first '=' only.
        local key="${line%%=*}"
        local value="${line#*=}"

        # Trim whitespace around the key (Bash 3.2 compatible).
        key="${key#"${key%%[![:space:]]*}"}"
        key="${key%"${key##*[![:space:]]}"}"
        if [[ -z "${key}" || "${key}" == "${line}" ]]; then
            continue
        fi

        # Strip a single layer of matching quotes.
        if [[ "${value}" == \"*\" && "${value}" == *\" ]]; then
            value="${value:1:${#value}-2}"
        elif [[ "${value}" == \'*\' && "${value}" == *\' ]]; then
            value="${value:1:${#value}-2}"
        fi

        # Do NOT clobber values already set in the shell — env wins over file.
        if [[ -z "${!key+x}" ]]; then
            export "${key}=${value}"
        fi
    done <"${env_file}"
}
