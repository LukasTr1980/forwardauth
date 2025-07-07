#!/bin/sh -e

export JWT_SECRET="$(cat /run/secrets/jwt_secret)"

exec "$@"