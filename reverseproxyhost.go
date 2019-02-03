package main

import (
	"github.com/labstack/echo"
	"github.com/labstack/echo/middleware"
	log "github.com/sirupsen/logrus"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
)

type (
	ReverseProxyHost struct {
		ReverseProxy *echo.Echo
	}
)

type HostConfig struct {
	ServiceRootURL         string   `yaml:"service_root_url"`
	IdpMetadataURL         string   `yaml:"idp_metadata_url"`
	Targets                []string `yaml:"targets"`
	NoCache                bool     `yaml:"no_cache"`
	AllowIDPInitiated      bool     `yaml:"allow_idp_initiated"`
	AddAttributesAsHeaders []string `yaml:"add_attributes_as_headers"`
}

func NewReverseProxyDirector(balancer middleware.ProxyBalancer) func(req *http.Request) {
	director := func(req *http.Request) {
		target := balancer.Next().URL
		targetQuery := target.RawQuery
		req.URL.Scheme = target.Scheme
		req.URL.Host = target.Host
		req.URL.Path = singleJoiningSlash(target.Path, req.URL.Path)
		req.Host = target.Host
		if targetQuery == "" || req.URL.RawQuery == "" {
			req.URL.RawQuery = targetQuery + req.URL.RawQuery
		} else {
			req.URL.RawQuery = targetQuery + "&" + req.URL.RawQuery
		}
		if _, ok := req.Header["User-Agent"]; !ok {
			// explicitly disable User-Agent so it's not set to default value
			req.Header.Set("User-Agent", "")
		}
	}
	return director
}

func singleJoiningSlash(a, b string) string {
	aslash := strings.HasSuffix(a, "/")
	bslash := strings.HasPrefix(b, "/")
	switch {
	case aslash && bslash:
		return a + b[1:]
	case !aslash && !bslash:
		return a + "/" + b
	}
	return a + b
}

func (s *Server) NewReverseProxyHost(config HostConfig) *ReverseProxyHost {
	var targets []*middleware.ProxyTarget

	// Parse target URLs
	for _, target := range config.Targets {
		url, err := url.Parse(target)
		if err != nil {
			log.WithFields(log.Fields{
				"target": target,
				"error":  err.Error()}).Fatal("could not parse host target URL")
		}

		proxyTarget := middleware.ProxyTarget{URL: url}
		targets = append(targets, &proxyTarget)
	}

	samlSP := s.NewSamlSP(config)

	proxyHost := echo.New()
	proxyHost.Use(middleware.Logger())
	proxyHost.Use(middleware.Recover())

	if config.NoCache {
		// Remove auth'd upstream hosts' client caching headers (session expiration)
		proxyHost.Use(NoCache())
	}

	director := NewReverseProxyDirector(middleware.NewRoundRobinBalancer(targets))
	reverseProxy := &httputil.ReverseProxy{Director: director}

	// This endpoint handles SAML auth flow
	proxyHost.Any("/saml/*", echo.WrapHandler(samlSP))
	proxyHost.Any("/*",
		echo.WrapHandler(reverseProxy),
		echo.WrapMiddleware(samlSP.RequireAccount),
		samlHeaders(config),
	)

	return &ReverseProxyHost{
		ReverseProxy: proxyHost,
	}
}
