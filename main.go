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

	"net/http/pprof"

	log "github.com/sirupsen/logrus"
	"github.com/crewjam/saml/samlsp"
	"github.com/vulcand/oxy/buffer"
	"github.com/vulcand/oxy/cbreaker"
	"github.com/vulcand/oxy/forward"
	"github.com/vulcand/oxy/ratelimit"
	"github.com/vulcand/oxy/roundrobin"
	"github.com/vulcand/oxy/trace"
	"github.com/vulcand/oxy/utils"
	goji "goji.io"
	"goji.io/pat"
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
	RateLimitAvgMinute   int64         `yaml:"rate_limit_avg_minute"`
	RateLimitBurstSecond int64         `yaml:"rate_limit_burst_second"`
	TraceRequestHeaders  []string      `yaml:"trace_request_headers"`
	CookieMaxAge         time.Duration `yaml:"cookie_max_age"`
	LogLevel             string        `yaml:"log_level"`
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

func attachProfiler(router *goji.Mux) {
	router.HandleFunc(pat.New("/debug/pprof/"), pprof.Index)
	router.HandleFunc(pat.New("/debug/pprof/cmdline"), pprof.Cmdline)
	router.HandleFunc(pat.New("/debug/pprof/profile"), pprof.Profile)
	router.HandleFunc(pat.New("/debug/pprof/symbol"), pprof.Symbol)

	// Manually add support for paths linked to by index page at /debug/pprof/
	router.Handle(pat.New("/debug/pprof/goroutine"), pprof.Handler("goroutine"))
	router.Handle(pat.New("/debug/pprof/heap"), pprof.Handler("heap"))
	router.Handle(pat.New("/debug/pprof/threadcreate"), pprof.Handler("threadcreate"))
	router.Handle(pat.New("/debug/pprof/block"), pprof.Handler("block"))
}

func main() {
	var C Config
	C.getConf()

	log.SetFormatter(&log.JSONFormatter{})
	log.SetOutput(os.Stdout)
	logLevel, err := log.ParseLevel(C.LogLevel)
	if err != nil {
		log.Fatal(err)
	}
	log.SetLevel(logLevel)

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
			time.Sleep(60 * time.Second)
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
		CookieMaxAge:   C.CookieMaxAge,
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
	router := goji.NewMux()

	if logLevel == log.DebugLevel || logLevel == log.InfoLevel {
		attachProfiler(router)
	}

	// This endpoint handles SAML auth flow
	router.Handle(pat.New("/saml/*"), samlSP)
	// These endpoints require valid session cookie
	router.Handle(pat.New("/*"), samlSP.RequireAccount(buffer))

	srv := &http.Server{
		Addr:    fmt.Sprintf("%s:%d", C.ListenInterface, C.ListenPort),
		Handler: router,
		// This breaks streaming requests
		ReadTimeout: 45 * time.Second,
		// This breaks long downloads
		WriteTimeout: 45 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	log.Fatal(srv.ListenAndServe())
}
