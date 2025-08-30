#!/bin/sh

staged_files=$(git diff --name-only --cached)
if [ -z "$staged_files" ]; then
	git add .
fi
git commit --amend --no-edit
git push --force-with-lease
