FROM golang:1.22-alpine AS builder

WORKDIR /app

COPY go.mod ./
# RUN go mod download # (No dependencies yet, so go mod download is optional, keeping it here for future proofing)
RUN go mod download

COPY . .
RUN go build -o pwdmanager main.go

FROM alpine:latest

WORKDIR /root/
COPY --from=builder /app/pwdmanager .

ENTRYPOINT ["./pwdmanager"]
