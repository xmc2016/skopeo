#!/bin/bash

IFS=$'\n'
files=( $(find . -name '*.go' | grep -v '^./vendor/' | sort || true) )
unset IFS

badFiles=()
for f in "${files[@]}"; do
	if [ "$(gofmt -s -l < $f)" ]; then
		badFiles+=( "$f" )
	fi
done

if [ ${#badFiles[@]} -eq 0 ]; then
	echo 'Congratulations!  All Go source files are properly formatted.'
else
	{
		echo "These files are not properly gofmt'd:"
		for f in "${badFiles[@]}"; do
			echo " - $f"
		done
		echo
		echo 'Please reformat the above files using "gofmt -s -w" and commit the result.'
		echo
	} >&2
	exit 1
fi
