# Copyright 2026 OpenSourceOM
# SPDX-License-Identifier: Apache-2.0

FROM golang:1.27.0-alpine@sha256:4c9fe60190a2a3350ddc51de80d0224b8a6698d12bdfc999fee45ea9d6c46dbc AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /om ./cmd/om

FROM alpine:3.20@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc
RUN apk add --no-cache ca-certificates
COPY --from=builder /om /usr/local/bin/om
WORKDIR /app
COPY go.mod ./
COPY migrations/ ./migrations/
EXPOSE 8080
ENTRYPOINT ["om"]
CMD ["serve"]
