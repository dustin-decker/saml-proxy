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

	"github.com/crewjam/saml/samlsp"
	log "github.com/sirupsen/logrus"
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
	ListenInterface      string        `yaml:"listen_interface"`
	ListenPort           int           `yaml:"listen_port"`
	Targets              []string      `yaml:"targets"`
	IdpMetadataURL       string        `yaml:"idp_metadata_url"`
	ServiceRootURL       string        `yaml:"service_root_url"`
	Cert                 string        `yaml:"cert"`
	Key                  string        `yaml:"key"`
	RateLimitAvgMinute   int64         `yaml:"rate_limit_avg_minute"`
	RateLimitBurstSecond int64         `yaml:"rate_limit_burst_second"`
	TraceRequestHeaders  []string      `yaml:"trace_request_headers"`
	CookieMaxAge         time.Duration `yaml:"cookie_max_age"`
	LogLevel             string        `yaml:"log_level"`
}

func (C *Config) getConf() *Config {

	pwd, err := os.Getwd()
	checkErr(err)
	yamlFile, err := ioutil.ReadFile(path.Join(pwd, os.Args[1]))
	checkErr(err)
	err = yaml.Unmarshal(yamlFile, C)
	checkErr(err)

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
	checkErr(err)
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
	checkErr(err)
	keyPair.Leaf, err = x509.ParseCertificate(keyPair.Certificate[0])
	checkErr(err)

	idpMetadataURL, err := url.Parse(C.IdpMetadataURL)
	checkErr(err)

	rootURL, err := url.Parse(C.ServiceRootURL)
	checkErr(err)

	samlSP, err := samlsp.New(samlsp.Options{
		URL:            *rootURL,
		Key:            keyPair.PrivateKey.(*rsa.PrivateKey),
		Certificate:    keyPair.Leaf,
		IDPMetadataURL: idpMetadataURL,
		CookieMaxAge:   C.CookieMaxAge,
	})
	checkErr(err)

	// reverse proxy layer
	fwd, err := forward.New()
	checkErr(err)
	// rate-limiting layers
	extractor, err := utils.NewExtractor("client.ip")
	checkErr(err)
	rates := ratelimit.NewRateSet()
	err = rates.Add(time.Second, C.RateLimitAvgMinute*60, C.RateLimitBurstSecond)
	checkErr(err)
	rm, err := ratelimit.New(fwd, extractor, rates)
	checkErr(err)
	// circuit-breaker layer
	const triggerNetRatio = `NetworkErrorRatio() > 0.5`
	cb, err := cbreaker.New(rm, triggerNetRatio)
	checkErr(err)
	// load balancing layer
	lb, err := roundrobin.New(cb)
	checkErr(err)
	// trace layer
	trace, err := trace.New(lb, io.Writer(os.Stdout),
		trace.Optiontrace.RequestHeaders(C.TraceRequestHeaders...))
	checkErr(err)

	// buffer will read the request body and will replay the request again in case if forward returned status
	// corresponding to nework error (e.g. Gateway Timeout)
	buffer, err := buffer.New(trace, buffer.Retry(`IsNetworkError() && Attempts() < 3`))
	checkErr(err)

	for _, target := range C.Targets {
		targetURL, err := url.Parse(target)
		checkErr(err)
		// add target to the load balancer
		err = lb.UpsertServer(targetURL)
		checkErr(err)
	}

	// Use mux for explicit paths and so no other routes are accidently exposed
	router := goji.NewMux()

	if logLevel == log.DebugLevel {
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

func checkErr(err error) {
	if err != nil {
		log.Fatal(err)
	}
}
