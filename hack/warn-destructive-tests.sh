#!/usr/bin/env bash
set -e

# Set this to 1 to enable installation/modification of environment/services
export SKOPEO_CONTAINER_TESTS=${SKOPEO_CONTAINER_TESTS:-0}

if [[ "$SKOPEO_CONTAINER_TESTS" == "0" ]] && [[ "$CI" != "true" ]]; then
    (
    echo "***************************************************************"
    echo "WARNING: Executing tests directly on the local development"
    echo "         host is highly discouraged.  Many important items"
    echo "         will be skipped.  For manual execution, please utilize"
    echo "         the Makefile targets WITHOUT the '-local' suffix."
    echo "***************************************************************"
    ) > /dev/stderr
    sleep 5
fi
