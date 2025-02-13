FROM golang:1.24.0 AS builder

WORKDIR /app

COPY go.mod go.sum ./

RUN go mod download

COPY . .

RUN CGO_ENABLED=0 go build -o /app/source ./client/router

FROM alpine:3.21.2 AS final

COPY --from=builder /app/source /app/source

CMD ["/app/source"]
