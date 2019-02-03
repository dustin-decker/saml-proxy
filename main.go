package main

import (
	"fmt"
	"github.com/labstack/echo"
	log "github.com/sirupsen/logrus"
	"net/url"
)

func main() {
	server := NewServer()
	hosts := map[string]*ReverseProxyHost{}
	e := server.Echo

	// Create host reverse proxies
	for _, host := range server.config.Hosts {
		rootURL, err := url.Parse(host.ServiceRootURL)
		if err != nil {
			log.WithFields(log.Fields{
				"service_root_url": host.ServiceRootURL,
				"error":            err.Error()}).Fatal("could not parse service root URL")
		}
		hosts[rootURL.Host] = server.NewReverseProxyHost(host)
	}

	e.Any("/*", func(c echo.Context) (err error) {
		req := c.Request()
		res := c.Response()

		// Get request Host
		host := hosts[req.Host]

		if host == nil {
			err = echo.ErrNotFound
		} else {
			host.ReverseProxy.ServeHTTP(res, req)
		}
		return
	})

	address := fmt.Sprintf("%v:%d", server.config.ListenInterface, server.config.ListenPort)
	e.Logger.Fatal(e.Start(address))
}
