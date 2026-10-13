# Copyright 2026 OpenSourceOM
# SPDX-License-Identifier: Apache-2.0

FROM golang:1.27.2-alpine@sha256:f92b6ef800e499660581efdabdf25d9d817a9d124eaf900924f0504e7e27e12d AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /om ./cmd/om

FROM alpine:3.24@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6
RUN apk add --no-cache ca-certificates
COPY --from=builder /om /usr/local/bin/om
WORKDIR /app
COPY go.mod ./
COPY migrations/ ./migrations/
EXPOSE 8080
ENTRYPOINT ["om"]
CMD ["serve"]
