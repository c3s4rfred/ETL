FROM ubuntu:latest

RUN apt update
RUN apt install -y golang wget zip unzip
COPY main.go .
COPY errors.go .
COPY go.mod .
COPY go.sum .
ENTRYPOINT go run .