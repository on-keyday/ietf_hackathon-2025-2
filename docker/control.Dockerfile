FROM golang:1.24.0 AS builder

WORKDIR /app

COPY ./gobgp/go.mod ./gobgp/go.sum ./

RUN go mod download

COPY ./gobgp .

COPY ./docker/gobgpd.yml /app/gobgpd.yml
COPY ./docker/runbgp.sh /app/runbgp.sh
RUN chmod +x /app/runbgp.sh

RUN CGO_ENABLED=0 go build -o /app/gobgp ./cmd/gobgp
RUN CGO_ENABLED=0 go build -o /app/gobgpd ./cmd/gobgpd

FROM alpine:3.21.2 AS final

# add tcpdump
RUN apk add --no-cache tcpdump

COPY --from=builder /app/gobgp /app/gobgp
COPY --from=builder /app/gobgpd /app/gobgpd
COPY --from=builder /app/gobgpd.yml /app/gobgpd.yml
COPY --from=builder /app/runbgp.sh /app/runbgp.sh

CMD ["/bin/sh", "/app/runbgp.sh"]
