FROM golang:latest AS builder

WORKDIR /app

COPY go.mod go.sum ./

RUN go mod download

COPY . .

RUN CGO_ENABLED=0 go build -o /app/main ./client/main.go

FROM alpine:3.13

COPY --from=builder /app/main /app/main

CMD ["/app/main"]