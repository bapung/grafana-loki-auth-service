FROM golang:1.23 AS builder

RUN apt update && apt install -y build-essential

WORKDIR /app
COPY go.mod ./
# If you have a go.sum file, uncomment the next line
COPY go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=1 GOOS=linux go build -a -o auth-service .

FROM gcr.io/distroless/static-debian12
# Copy necessary shared libraries
COPY --from=builder /lib64 /lib64
COPY --from=builder /usr/lib64 /usr/lib64
COPY --from=builder /lib /lib
COPY --from=builder /usr/lib /usr/lib
COPY --from=builder /app/auth-service .
EXPOSE 8000
CMD ["/auth-service"]
