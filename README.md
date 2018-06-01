# saml-proxy

[![Travis-CI Build Status](https://travis-ci.com/dustin-decker/saml-proxy.svg?branch=master)](https://travis-ci.com/dustin-decker/saml-proxy)
[![Docker Hub Build Status](https://img.shields.io/docker/build/dustindecker/saml-proxy.svg)](https://hub.docker.com/r/dustindecker/saml-proxy/)

A SAML 2.0 auth providing reverse proxy with fancy features like roundrobin
load balancing, a buffer for retrying requests, a Hystrix-style circuit breaker,
and rate limiting. The proxy can pass SAML attributes such as username and groups to the target application.

## Roadmap

- Add TLS termination
- Add optional mutual TLS authentication
- Support built-in RBAC in addition to passing users and groups upstream (current behavior)
- Support separate upstream targets by hostname
- Support custom entity descriptor
- Healthcheck and metrics API

## Get up and running

Install deps:
`dep ensure`

Build:
`go build`

Configure your stuff based on `config.example.yaml` and name it `config.yaml`

Create your cert and key

```openssl req -x509 -newkey rsa:2048 -keyout myservice.key -out myservice.cert -days 365 -nodes -subj "/CN=myservice.example.com"```

Compile and run with `-c /path/to/config.yaml`