#!/bin/bash

export CGO_CFLAGS="-I/usr/local/include/pbc -I/opt/homebrew/opt/gmp/include"
export CGO_LDFLAGS="-L/usr/local/lib -L/opt/homebrew/opt/gmp/lib -lpbc -lgmp"

go run cmd/decryption-service/main.go
