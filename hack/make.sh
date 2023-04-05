#!/usr/bin/env bash
set -e

# This script builds various binary from a checkout of the skopeo
# source code. DO NOT CALL THIS SCRIPT DIRECTLY.
#
# Requirements:
# - The current directory should be a checkout of the skopeo source code
#   (https://github.com/containers/skopeo). Whatever version is checked out
#   will be built.
# - The script is intended to be run inside the container specified
#   in the output of hack/get_fqin.sh
# - The right way to call this script is to invoke "make" from
#   your checkout of the skopeo repository.
#   the Makefile will do a "docker build -t skopeo ." and then
#   "docker run hack/make.sh" in the resulting image.
#

set -o pipefail

export SKOPEO_PKG='github.com/containers/skopeo'
export SCRIPTDIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

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

echo

go_test_dir() {
	dir=$1
	(
		echo '+ go test' $TESTFLAGS ${BUILDTAGS:+-tags "$BUILDTAGS"} "${SKOPEO_PKG}${dir#.}"
		cd "$dir"
		go test $TESTFLAGS ${BUILDTAGS:+-tags "$BUILDTAGS"}
	)
}

bundle() {
	local bundle="$1"; shift
	echo "---> Making bundle: $(basename "$bundle")"
	source "$SCRIPTDIR/make/$bundle" "$@"
}

main() {
	if [ $# -lt 1 ]; then
		echo 'At least one "bundle" argument expected' >&2
		return 1
	fi
	for bundle in $@; do
		bundle "$bundle"
		echo
	done
}

main "$@"
