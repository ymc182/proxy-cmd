package main

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/teslamotors/vehicle-command/internal/log"
	"github.com/teslamotors/vehicle-command/pkg/cli"
	"github.com/teslamotors/vehicle-command/pkg/protocol"
	"github.com/teslamotors/vehicle-command/pkg/proxy"
)

const (
	cacheSize   = 10000 // Number of cached vehicle sessions
	defaultPort = 443
)

const (
	EnvTlsCert = "TESLA_HTTP_PROXY_TLS_CERT"
	EnvTlsKey  = "TESLA_HTTP_PROXY_TLS_KEY"
	EnvHost    = "TESLA_HTTP_PROXY_HOST"
	EnvPort    = "TESLA_HTTP_PROXY_PORT"
	EnvTimeout = "TESLA_HTTP_PROXY_TIMEOUT"
	EnvVerbose = "TESLA_VERBOSE"
)

const nonLocalhostWarning = `
Do not listen on a network interface without adding client authentication. Unauthorized clients may
be used to create excessive traffic from your IP address to Tesla's servers, which Tesla may respond
to by rate limiting or blocking your connections.`

type HttpProxyConfig struct {
	keyFilename  string
	certFilename string
	verbose      bool
	host         string
	port         int
	timeout      time.Duration
}

var (
	httpConfig = &HttpProxyConfig{}
	apiKey     string
)

func init() {
	flag.StringVar(&httpConfig.certFilename, "cert", "", "TLS certificate chain `file` with concatenated server, intermediate CA, and root CA certificates")
	flag.StringVar(&httpConfig.keyFilename, "tls-key", "", "Server TLS private key `file`")
	flag.BoolVar(&httpConfig.verbose, "verbose", false, "Enable verbose logging")
	flag.StringVar(&httpConfig.host, "host", "localhost", "Proxy server `hostname`")
	flag.IntVar(&httpConfig.port, "port", defaultPort, "`Port` to listen on")
	flag.DurationVar(&httpConfig.timeout, "timeout", proxy.DefaultTimeout, "Timeout interval when sending commands")
	flag.StringVar(&apiKey, "api-key", "", "API key for authentication")
}

func Usage() {
	out := flag.CommandLine.Output()
	fmt.Fprintf(out, "Usage: %s [OPTION...]\n", os.Args[0])
	fmt.Fprintf(out, "\nA server that exposes a REST API for sending commands to Tesla vehicles")
	fmt.Fprintln(out, "")
	fmt.Fprintln(out, nonLocalhostWarning)
	fmt.Fprintln(out, "")
	fmt.Fprintln(out, "Options:")
	flag.PrintDefaults()
}

func main() {
	config, err := cli.NewConfig(cli.FlagPrivateKey)

	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load credential configuration: %s\n", err)
		os.Exit(1)
	}

	defer func() {
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %s\n", err)
			os.Exit(1)
		}
	}()

	flag.Usage = Usage
	config.RegisterCommandLineFlags()
	flag.Parse()
	readFromEnvironment()
	config.ReadFromEnvironment()

	if httpConfig.verbose {
		log.SetLevel(log.LevelDebug)
	}

	if httpConfig.host != "localhost" {
		fmt.Fprintln(os.Stderr, nonLocalhostWarning)
	}

	var skey protocol.ECDHPrivateKey
	skey, err = config.PrivateKey()
	if err != nil {
		return
	}

	if tlsPublicKey, err := protocol.LoadPublicKey(httpConfig.keyFilename); err == nil {
		if bytes.Equal(tlsPublicKey.Bytes(), skey.PublicBytes()) {
			fmt.Fprintln(os.Stderr, "It is unsafe to use the same private key for TLS and command authentication.")
			fmt.Fprintln(os.Stderr, "")
			fmt.Fprintln(os.Stderr, "Generate a new TLS key for this server.")
			return
		}
	}

	log.Debug("Creating proxy")
	p, err := proxy.New(context.Background(), skey, cacheSize)
	if err != nil {
		return
	}
	p.Timeout = httpConfig.timeout

	
	handler := apiKeyMiddleware(p)

	addr := fmt.Sprintf("%s:%d", httpConfig.host, httpConfig.port)
	log.Info("Listening on %s", addr)

	log.Error("Server stopped: %s", http.ListenAndServeTLS(addr, httpConfig.certFilename, httpConfig.keyFilename, handler))
}

func apiKeyMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check for API key in the request header
		providedKey := r.Header.Get("X-API-Key")
		if providedKey == "" {
			http.Error(w, "Missing API key", http.StatusUnauthorized)
			return
		}

		// Validate the API key
		if providedKey != apiKey {
			http.Error(w, "Invalid API key", http.StatusUnauthorized)
			return
		}

		// If the API key is valid, call the next handler
		next.ServeHTTP(w, r)
	})
}

// readConfig applies configuration from environment variables.
// Values are not overwritten.
func readFromEnvironment() error {
	if httpConfig.certFilename == "" {
		httpConfig.certFilename = os.Getenv(EnvTlsCert)
	}

	if httpConfig.keyFilename == "" {
		httpConfig.keyFilename = os.Getenv(EnvTlsKey)
	}

	if httpConfig.host == "localhost" {
		host, ok := os.LookupEnv(EnvHost)
		if ok {
			httpConfig.host = host
		}
	}

	if !httpConfig.verbose {
		if verbose, ok := os.LookupEnv(EnvVerbose); ok {
			httpConfig.verbose = verbose != "false" && verbose != "0"
		}
	}

	var err error
	if httpConfig.port == defaultPort {
		if port, ok := os.LookupEnv(EnvPort); ok {
			httpConfig.port, err = strconv.Atoi(port)
			if err != nil {
				return fmt.Errorf("invalid port: %s", port)
			}
		}
	}

	if httpConfig.timeout == proxy.DefaultTimeout {
		if timeoutEnv, ok := os.LookupEnv(EnvTimeout); ok {
			httpConfig.timeout, err = time.ParseDuration(timeoutEnv)
			if err != nil {
				return fmt.Errorf("invalid timeout: %s", timeoutEnv)
			}
		}
	}

	return nil
}
