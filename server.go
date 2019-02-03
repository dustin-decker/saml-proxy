package main

import (
	"flag"
	"github.com/labstack/echo"
	"github.com/labstack/echo/middleware"
	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"
	"io/ioutil"
	"os"
	"path/filepath"
	"time"
)

type ServerConfig struct {
	ListenInterface string        `yaml:"listen_interface"`
	ListenPort      int           `yaml:"listen_port"`
	CertPath        string        `yaml:"cert_path"`
	KeyPath         string        `yaml:"key_path"`
	CookieMaxAge    time.Duration `yaml:"cookie_max_age"`
	LogLevel        string        `yaml:"log_level"`
	Hosts           []HostConfig  `yaml:"hosts"`
}

type Server struct {
	config ServerConfig
	Echo   *echo.Echo
}

func (C *ServerConfig) getConf(configPath string) {
	yamlFile, err := ioutil.ReadFile(configPath)
	if err != nil {
		log.WithFields(log.Fields{
			"config_path": configPath,
			"error":       err.Error()}).Fatal("could not read config")
	}
	err = yaml.Unmarshal(yamlFile, C)
	if err != nil {
		log.WithFields(log.Fields{
			"config_path": configPath,
			"error":       err.Error()}).Fatal("could not parse config")
	}
}

func NewServer() *Server {
	var configPath string
	flag.StringVar(&configPath, "c", "config.yaml", "path to the config file")
	flag.Parse()
	var C ServerConfig
	absPath, err := filepath.Abs(configPath)
	if err != nil {
		log.WithFields(log.Fields{
			"config_path": configPath,
			"error":       err.Error()}).Fatal("could not determine absolute path for config")
	}
	C.getConf(absPath)

	log.Print("config loaded")
	log.SetFormatter(&log.JSONFormatter{})
	log.SetOutput(os.Stdout)
	logLevel, err := log.ParseLevel(C.LogLevel)
	if err != nil {
		log.WithFields(log.Fields{
			"log_level": C.LogLevel,
			"error":     err.Error()}).Fatal("could not parse log level")
	}
	log.SetLevel(logLevel)

	e := echo.New()
	e.Use(middleware.Recover())
	e.Use(middleware.Logger())

	s := Server{config: C, Echo: e}
	return &s
}
