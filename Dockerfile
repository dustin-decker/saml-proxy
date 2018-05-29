# Build stage
ARG GO_VERSION=1.10
ARG PROJECT_PATH=/go/src/github.com/dustin-decker/saml-proxy
FROM golang:${GO_VERSION}-alpine AS builder
RUN apk add --no-cache git
WORKDIR /go/src/github.com/dustin-decker/saml-proxy
RUN go get -u github.com/golang/dep/cmd/dep
RUN adduser -D -u 59999 container-user
COPY ./ ${PROJECT_PATH}
RUN export PATH=$PATH:`go env GOHOSTOS`-`go env GOHOSTARCH` \
    && dep ensure \
    && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build --ldflags '-extldflags "-static"' -o bin/saml-proxy main.go \
    && go test $(go list ./... | grep -v /vendor/)

# Production image
FROM scratch
COPY --from=builder /etc/passwd /etc/passwd
COPY --from=builder /go/src/github.com/dustin-decker/saml-proxy/bin/saml-proxy /saml-proxy
USER container-user
ENTRYPOINT ["/saml-proxy"]