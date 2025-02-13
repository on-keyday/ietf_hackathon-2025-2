FROM golang:1.24.0 AS builder

WORKDIR /app

COPY go.mod go.sum ./

RUN go mod download

COPY . .

RUN CGO_ENABLED=0 go build -o /app/destination ./client/router

FROM alpine:3.21.2 AS final

COPY --from=builder /app/destination /app/destination

CMD ["/app/destination"]
