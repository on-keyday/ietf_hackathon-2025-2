FROM golang:1.24.0 AS builder

WORKDIR /app

COPY go.mod go.sum ./gobgp/go.mod ./gobgp/go.sum ./

RUN --mount=type=cache,target=/go/pkg/mod \
     go mod download

COPY . .

RUN --mount=type=cache,target=/go/pkg/mod\
     CGO_ENABLED=0 go build -o /app/router ./client/router


RUN --mount=type=cache,target=/go/pkg/mod\
     cd gobgp &&  CGO_ENABLED=0 go build -o /app/gobgp ./cmd/gobgp
RUN --mount=type=cache,target=/go/pkg/mod\
     cd gobgp &&  CGO_ENABLED=0 go build -o /app/gobgpd ./cmd/gobgpd

FROM alpine:3.21.2 AS final

COPY --from=builder /app/router /app/router
COPY --from=builder /app/gobgp /app/gobgp
COPY --from=builder /app/gobgpd /app/gobgpd
RUN apk add --no-cache tcpdump
COPY ./docker/gobgpd_dst.yml /app/gobgpd.yml
COPY ./docker/run_bgprouter.sh /app/run_bgprouter.sh

CMD ["/bin/sh", "/app/run_bgprouter.sh","dst"]
