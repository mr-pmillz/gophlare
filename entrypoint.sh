#!/usr/bin/env bash

# if Gitlab CI exec /bin/bash
if [[ -n "$CI" ]]; then
    exec /bin/bash
else
    exec "$@"
fi