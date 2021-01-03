#!/bin/sh

# Pass through arguments
cd /app
exec ./simpleauth "${@}"
