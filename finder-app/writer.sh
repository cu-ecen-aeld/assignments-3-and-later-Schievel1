#!/usr/bin/env sh

main() {
  if [ "$#" -ne 2 ]; then
    printf "ERR: 2 arguments required, found %d\n" "$#"
    exit 1
  fi

  mkdir -p "$(dirname "$1")" || printf "Could not create directory %s for the file.\n" "$(dirname "$1")" || exit 1
  echo "$2" > "$1" || printf "could not write %s into %s\n" "$2" "$1" || exit 1
}

main "$@"
