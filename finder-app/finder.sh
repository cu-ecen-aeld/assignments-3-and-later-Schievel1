#!/usr/bin/env sh

main() {
  if [ "$#" -ne 2 ]; then
    printf "ERR: 2 arguments required, found %d\n" "$#"
    exit 1
  fi
  if ! [ -d "$1"  ]; then
    printf "ERR: can not find directory %s\n" "$1"
    exit 1
  fi

  files_no=$(find "$1" -type f | wc -l)
  found_no=$(grep -r "$2" "$1" | wc -l)

  printf "The number of files are %s and the number of matching lines are %s\n" "${files_no}" "${found_no}"
}

main "$@"
