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
		panic(err)
	}
	keyPair.Leaf, err = x509.ParseCertificate(keyPair.Certificate[0])
	if err != nil {
		panic(err)
	}

	idpMetadataURL, err := url.Parse(C.IdpMetadataURL)
	if err != nil {
		panic(err)
	}

	rootURL, err := url.Parse(C.ServiceRootURL)
	if err != nil {
		panic(err)
	}

	samlSP, _ := samlsp.New(samlsp.Options{
		URL:            *rootURL,
		Key:            keyPair.PrivateKey.(*rsa.PrivateKey),
		Certificate:    keyPair.Leaf,
		IDPMetadataURL: idpMetadataURL,
	})

	// reverse proxy layer
	fwd, _ := forward.New()
	// rate-limiting layers
	extractor, _ := utils.NewExtractor("client.ip")
	rates := ratelimit.NewRateSet()
	rates.Add(time.Second, C.RateLimitAvgMinute*60, C.RateLimitBurstSecond)
	rm, _ := ratelimit.New(fwd, extractor, rates)
	// circuit-breaker layer
	const triggerNetRatio = `NetworkErrorRatio() > 0.5`
	cb, _ := cbreaker.New(rm, triggerNetRatio)
	// load balancing layer
	lb, _ := roundrobin.New(cb)
	// trace layer
	trace, _ := trace.New(lb, io.Writer(os.Stdout),
		trace.Option(trace.RequestHeaders(C.TraceRequestHeaders...)))

	// buffer will read the request body and will replay the request again in case if forward returned status
	// corresponding to nework error (e.g. Gateway Timeout)
	buffer, _ := buffer.New(trace, buffer.Retry(`IsNetworkError() && Attempts() < 3`))

	for _, target := range C.Targets {
		targetURL, err := url.Parse(target)
		if err != nil {
			panic(err)
		}
		// add target to the load balancer
		lb.UpsertServer(targetURL)
	}

	// This endpoint handles SAML auth flow
	http.Handle("/saml/", samlSP)
	// Any other endpoints require valid session cookie
	http.Handle("/", samlSP.RequireAccount(buffer))
	http.ListenAndServe(fmt.Sprintf("%s:%d", C.ListenInterface, C.ListenPort), nil)
}
