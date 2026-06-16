#!/bin/sh
# Entry point for the Spring Taint GitHub Action / Docker image.
# Reads GitHub Action inputs (INPUT_*) and runs a scan.
set -e

if [ -z "${INPUT_PATH}" ]; then
  echo "error: 'path' input is required (compiled classes or JAR to scan)" >&2
  exit 2
fi

set -- scan "${INPUT_PATH}"
[ -n "${INPUT_LIBS}" ]     && set -- "$@" --libs "${INPUT_LIBS}"
[ -n "${INPUT_CONFIG}" ]   && set -- "$@" --config "${INPUT_CONFIG}"
[ -n "${INPUT_SEVERITY}" ] && set -- "$@" --severity "${INPUT_SEVERITY}"
[ -n "${INPUT_OUTPUT}" ]   && set -- "$@" --output "${INPUT_OUTPUT}"

echo "spring-taint $*"
exec java -Xmx4g -jar /opt/spring-taint/spring-taint.jar "$@"
