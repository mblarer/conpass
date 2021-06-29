#!/bin/bash

cd "$(dirname "$(readlink -f "$0")")"

OPT_GO="--go_out=. --go_opt=paths=source_relative"
OPT_GRPC="--go-grpc_out=. --go-grpc_opt=paths=source_relative"
CMD="protoc $OPT_GO $OPT_GRPC src/proto/negotiation/negotiation.proto"

docker build -t scion-ipn .
docker run -v "$(pwd)/proto:/go/src/proto" -it scion-ipn sh -c "$CMD"
