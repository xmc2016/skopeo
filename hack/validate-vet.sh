#!/bin/bash

errors=$(go vet -tags="${BUILDTAGS}" ./... 2>&1)

if [ -z "$errors" ]; then
	echo 'Congratulations!  All Go source files have been vetted.'
else
	{
		echo "Errors from go vet:"
		echo "$errors"
		echo
		echo 'Please fix the above errors. You can test via "go vet" and commit the result.'
		echo
	} >&2
	exit 1
fi
