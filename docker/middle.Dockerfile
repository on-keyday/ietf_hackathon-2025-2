FROM golang:1.24.0 AS builder

WORKDIR /app

COPY go.mod go.sum ./gobgp/go.mod ./gobgp/go.sum ./

RUN  --mount=type=cache,target=/go/pkg/mod \
  go mod download

COPY . .

RUN --mount=type=cache,target=/go/pkg/mod\
     CGO_ENABLED=0 go build -o /app/router ./client/router

FROM alpine:3.21.2 AS final

COPY --from=builder /app/router /app/router


CMD ["/app/router","-mode","router"]
