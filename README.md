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

## Build

Install deps:
`dep ensure`

Build:
`go build`

## Usage

First, create your cert and key. They are required for signing sessions.

```openssl req -x509 -newkey rsa:2048 -keyout private.key -out public.crt -days 365 -nodes -subj "/CN=myservice.example.com"```

There are three options for configuration:

- YAML file
- Environment variables
- CLI flags

You can customize [`config.example.yaml`](config.example.yaml) and run with the `configpath` flag or env var, otherwise this is the usage:

```bash
./saml-proxy -h
Usage of ./saml-proxy:
  -addattributesasheaders
    	Change value of AddAttributesAsHeaders. (default [])
  -certpath
    	Change value of CertPath. (default public.crt)
  -configpath
    	Change value of ConfigPath.
  -cookiemaxage
    	Change value of CookieMaxAge. (default 4h0m0s)
  -idpmetadataurl
    	Change value of IdpMetadataURL.
  -keypath
    	Change value of KeyPath. (default private.key)
  -listeninterface
    	Change value of ListenInterface. (default 0.0.0.0)
  -listenport
    	Change value of ListenPort. (default 9090)
  -loglevel
    	Change value of LogLevel. (default info)
  -ratelimitavgsecond
    	Change value of RateLimitAvgSecond. (default 300)
  -ratelimitburstsecond
    	Change value of RateLimitBurstSecond. (default 500)
  -servicerooturl
    	Change value of ServiceRootURL.
  -targets
    	Change value of Targets. (default [])
  -tracerequestheaders
    	Change value of TraceRequestHeaders. (default [])

Generated environment variables:
   CONFIG_ADDATTRIBUTESASHEADERS
   CONFIG_CERTPATH
   CONFIG_CONFIGPATH
   CONFIG_COOKIEMAXAGE
   CONFIG_IDPMETADATAURL
   CONFIG_KEYPATH
   CONFIG_LISTENINTERFACE
   CONFIG_LISTENPORT
   CONFIG_LOGLEVEL
   CONFIG_RATELIMITAVGSECOND
   CONFIG_RATELIMITBURSTSECOND
   CONFIG_SERVICEROOTURL
   CONFIG_TARGETS
   CONFIG_TRACEREQUESTHEADERS
```