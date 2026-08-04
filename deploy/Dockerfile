FROM golang:1.26-alpine AS build
WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 go build -o /honeypot ./cmd/honeypot

FROM gcr.io/distroless/static-debian12
WORKDIR /app

COPY --from=build /honeypot ./honeypot

ENTRYPOINT ["./honeypot"]