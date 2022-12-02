FROM ubuntu:latest

RUN apt update
RUN apt install -y golang wget gzip tar python3 python3-pip
RUN python3 -m pip install --user --upgrade cvdupdate
RUN python3 -m cvdupdate config set --dbdir /
COPY main.go .
COPY errors.go .
COPY go.mod .
COPY go.sum .
ENTRYPOINT go run .