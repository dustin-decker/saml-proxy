package main

import (
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"path"
	"runtime"
	"time"

	yaml "gopkg.in/yaml.v2"

	log "github.com/Sirupsen/logrus"
	"github.com/crewjam/saml/samlsp"
	"github.com/julienschmidt/httprouter"
	"github.com/vulcand/oxy/buffer"
	"github.com/vulcand/oxy/cbreaker"
	"github.com/vulcand/oxy/forward"
	"github.com/vulcand/oxy/ratelimit"
	"github.com/vulcand/oxy/roundrobin"
	"github.com/vulcand/oxy/trace"
	"github.com/vulcand/oxy/utils"
)

// Config for reverse proxy settings and RBAC users and groups
// Unmarshalled from config on disk
type Config struct {
	ListenInterface      string `yaml:"listen_interface"`
	ListenPort           int    `yaml:"listen_port"`
	Targets              []string
	IdpMetadataURL       string `yaml:"idp_metadata_url"`
	ServiceRootURL       string `yaml:"service_root_url"`
	Cert                 string
	Key                  string
	RateLimitAvgMinute   int64    `yaml:"rate_limit_avg_minute"`
	RateLimitBurstSecond int64    `yaml:"rate_limit_burst_second"`
	TraceRequestHeaders  []string `yaml:"trace_request_headers"`
}

func (C *Config) getConf() *Config {

	pwd, _ := os.Getwd()
	yamlFile, err := ioutil.ReadFile(path.Join(pwd, os.Args[1]))
	if err != nil {
		log.Error(err)
	}
	err = yaml.Unmarshal(yamlFile, C)
	if err != nil {
		log.Error(err)
	}

	return C
}

func main() {
	// Log as JSON instead of the default ASCII formatter.
	log.SetFormatter(&log.JSONFormatter{})

	// Output to stdout instead of the default stderr
	// Can be any io.Writer, see below for File example
	log.SetOutput(os.Stdout)

	// Only log the warning severity or above.
	log.SetLevel(log.WarnLevel)

	var C Config
	C.getConf()

	go func() {
		for {
			var m runtime.MemStats
			runtime.ReadMemStats(&m)
			log.WithFields(log.Fields{
				"alloc":              fmt.Sprintf("%v", m.Alloc),
				"total-alloc":        fmt.Sprintf("%v", m.TotalAlloc/1024),
				"sys":                fmt.Sprintf("%v", m.Sys/1024),
				"num-gc":             fmt.Sprintf("%v", m.NumGC),
				"goroutines":         fmt.Sprintf("%v", runtime.NumGoroutine()),
				"stop-pause-nanosec": fmt.Sprintf("%v", m.PauseTotalNs),
			}).Warn("Process stats")
			time.Sleep(15 * time.Second)
		}
	}()

	keyPair, err := tls.LoadX509KeyPair(C.Cert, C.Key)
	if err != nil {
		log.Fatal(err)
	}
	keyPair.Leaf, err = x509.ParseCertificate(keyPair.Certificate[0])
	if err != nil {
		log.Fatal(err)
	}

	idpMetadataURL, err := url.Parse(C.IdpMetadataURL)
	if err != nil {
		log.Fatal(err)
	}

	rootURL, err := url.Parse(C.ServiceRootURL)
	if err != nil {
		log.Fatal(err)
	}

	samlSP, _ := samlsp.New(samlsp.Options{
		URL:            *rootURL,
		Key:            keyPair.PrivateKey.(*rsa.PrivateKey),
		Certificate:    keyPair.Leaf,
		IDPMetadataURL: idpMetadataURL,
	})

	// reverse proxy layer
	fwd, err := forward.New()
	if err != nil {
		log.Fatal(err)
	}
	// rate-limiting layers
	extractor, err := utils.NewExtractor("client.ip")
	if err != nil {
		log.Fatal(err)
	}
	rates := ratelimit.NewRateSet()
	rates.Add(time.Second, C.RateLimitAvgMinute*60, C.RateLimitBurstSecond)
	rm, err := ratelimit.New(fwd, extractor, rates)
	if err != nil {
		log.Fatal(err)
	}
	// circuit-breaker layer
	const triggerNetRatio = `NetworkErrorRatio() > 0.5`
	cb, err := cbreaker.New(rm, triggerNetRatio)
	if err != nil {
		log.Fatal(err)
	}
	// load balancing layer
	lb, err := roundrobin.New(cb)
	if err != nil {
		log.Fatal(err)
	}
	// trace layer
	trace, err := trace.New(lb, io.Writer(os.Stdout),
		trace.Option(trace.RequestHeaders(C.TraceRequestHeaders...)))
	if err != nil {
		log.Fatal(err)
	}

	// buffer will read the request body and will replay the request again in case if forward returned status
	// corresponding to nework error (e.g. Gateway Timeout)
	buffer, err := buffer.New(trace, buffer.Retry(`IsNetworkError() && Attempts() < 3`))
	if err != nil {
		log.Fatal(err)
	}

	for _, target := range C.Targets {
		targetURL, err := url.Parse(target)
		if err != nil {
			log.Fatal(err)
		}
		// add target to the load balancer
		lb.UpsertServer(targetURL)
	}

	// Use mux for explicit paths and so no other routes are accidently exposed
	router := httprouter.New()

	// This endpoint handles SAML auth flow
	router.Handler("GET", "/saml/*path", samlSP)
	router.Handler("POST", "/saml/*path", samlSP)
	// These endpoints require valid session cookie
	router.Handler("GET", "/", samlSP.RequireAccount(buffer))
	router.Handler("POST", "/", samlSP.RequireAccount(buffer))
	router.Handler("PUT", "/", samlSP.RequireAccount(buffer))
	router.Handler("DELETE", "/", samlSP.RequireAccount(buffer))
	router.Handler("PATCH", "/", samlSP.RequireAccount(buffer))

	srv := &http.Server{
		Addr:         fmt.Sprintf("%s:%d", C.ListenInterface, C.ListenPort),
		Handler:      router,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	log.Fatal(srv.ListenAndServe())
}
