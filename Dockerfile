FROM golang:1.16-alpine

# Install Protocol Buffers, gRPC, and corresponding Go plugins
RUN apk add --no-cache protoc \
    && go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.26 \
    && go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.1
