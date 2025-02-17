FROM golang:1.24.0 AS builder

WORKDIR /app

COPY ./gobgp/go.mod ./gobgp/go.sum ./

RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download 

COPY ./gobgp .

COPY ./docker/gobgpd_ctrl.yml /app/gobgpd.yml
COPY ./docker/runbgp.sh /app/runbgp.sh
RUN chmod +x /app/runbgp.sh

RUN --mount=type=cache,target=/go/pkg/mod\
     CGO_ENABLED=0 go build -o /app/gobgp ./cmd/gobgp
RUN --mount=type=cache,target=/go/pkg/mod\
   CGO_ENABLED=0 go build -o /app/gobgpd ./cmd/gobgpd

FROM alpine:3.21.2 AS final

# add tcpdump
RUN apk add --no-cache tcpdump iproute2

COPY --from=builder /app/gobgp /app/gobgp
COPY --from=builder /app/gobgpd /app/gobgpd
COPY --from=builder /app/gobgpd.yml /app/gobgpd.yml
COPY --from=builder /app/runbgp.sh /app/runbgp.sh

CMD ["/bin/sh", "/app/runbgp.sh"]
