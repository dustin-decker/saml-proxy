package main

import (
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"github.com/crewjam/saml/samlsp"
	"github.com/labstack/echo"
	log "github.com/sirupsen/logrus"
	"net/url"
	"strings"
)

func samlHeaders(config HostConfig) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) (err error) {
			req := c.Request()
			attributes := samlsp.Token(req.Context()).Attributes
			for _, attr := range config.AddAttributesAsHeaders {
				if val, ok := attributes[attr]; ok {
					req.Header.Add("X-Saml-"+attr, strings.Join(val, " "))
				} else {
					log.WithFields(log.Fields{"attrs_available": attributes,
						"attr": attr}).Warn("given attr not in attributes")
				}
			}
			return next(c)
		}
	}
}

func (s *Server) NewSamlSP(hostConfig HostConfig) *samlsp.Middleware {
	keyPair, err := tls.LoadX509KeyPair(s.config.CertPath, s.config.KeyPath)
	if err != nil {
		log.WithFields(log.Fields{
			"cert_path": s.config.CertPath,
			"key_path":  s.config.KeyPath,
			"error":     err.Error()}).Fatal("could not load keypair")
	}
	keyPair.Leaf, err = x509.ParseCertificate(keyPair.Certificate[0])
	if err != nil {
		log.WithFields(log.Fields{
			"cert_path": s.config.CertPath,
			"error":     err.Error()}).Fatal("could not parse certificate")
	}

	idpMetadataURL, err := url.Parse(hostConfig.IdpMetadataURL)
	if err != nil {
		log.WithFields(log.Fields{
			"idp_metadata_url": hostConfig.IdpMetadataURL,
			"error":            err.Error()}).Fatal("could not parse metadata URL")
	}

	rootURL, err := url.Parse(hostConfig.ServiceRootURL)
	if err != nil {
		log.WithFields(log.Fields{
			"service_root_url": hostConfig.ServiceRootURL,
			"error":            err.Error()}).Fatal("could not parse service root URL")
	}

	// initialize SAML middleware
	samlSP, err := samlsp.New(samlsp.Options{
		URL:               *rootURL,
		Key:               keyPair.PrivateKey.(*rsa.PrivateKey),
		Certificate:       keyPair.Leaf,
		IDPMetadataURL:    idpMetadataURL,
		AllowIDPInitiated: hostConfig.AllowIDPInitiated,
		CookieMaxAge:      s.config.CookieMaxAge,
	})
	if err != nil {
		log.WithFields(log.Fields{"error": err.Error()}).Fatal("could not initialize SAML middleware")
	}
	return samlSP
}
