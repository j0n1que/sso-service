FROM golang:1.23

WORKDIR .


COPY . .

COPY config/local.yml ./config/

RUN go build -o="./bin/app" ./cmd/sso/main.go

ENTRYPOINT ["./bin/app"]

