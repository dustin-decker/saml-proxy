package main

import (
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/url"
	"os"

	log "github.com/Sirupsen/logrus"
	"github.com/crewjam/saml/samlsp"
	"github.com/vulcand/oxy/buffer"
	"github.com/vulcand/oxy/forward"
	"github.com/vulcand/oxy/roundrobin"
)

func main() {
	// Log as JSON instead of the default ASCII formatter.
	log.SetFormatter(&log.JSONFormatter{})

	// Output to stdout instead of the default stderr
	// Can be any io.Writer, see below for File example
	log.SetOutput(os.Stdout)

	// Only log the warning severity or above.
	log.SetLevel(log.InfoLevel)

	keyPair, err := tls.LoadX509KeyPair("myservice.cert", "myservice.key")
	if err != nil {
		panic(err)
	}
	keyPair.Leaf, err = x509.ParseCertificate(keyPair.Certificate[0])
	if err != nil {
		panic(err)
	}

	idpMetadataURL, err := url.Parse("https://someidp.com/43943")
	if err != nil {
		panic(err)
	}

	rootURL, err := url.Parse("http://localhost")
	if err != nil {
		panic(err)
	}

	samlSP, _ := samlsp.New(samlsp.Options{
		URL:            *rootURL,
		Key:            keyPair.PrivateKey.(*rsa.PrivateKey),
		Certificate:    keyPair.Leaf,
		IDPMetadataURL: idpMetadataURL,
	})

	fwd, _ := forward.New()
	lb, _ := roundrobin.New(fwd)

	// buffer will read the request body and will replay the request again in case if forward returned status
	// corresponding to nework error (e.g. Gateway Timeout)
	buffer, _ := buffer.New(lb, buffer.Retry(`IsNetworkError() && Attempts() < 2`))

	url1, _ := url.Parse("http://localhost:8080")
	lb.UpsertServer(url1)

	http.Handle("/saml/", samlSP)
	http.Handle("/", samlSP.RequireAccount(buffer))
	http.ListenAndServe(":80", nil)
}
