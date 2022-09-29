/*
Copyright 2022 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	"flag"
	"os"

	"github.com/spf13/pflag"
	ngx_config "k8s.io/ingress-nginx/internal/ingress/controller/config"
	"k8s.io/ingress-nginx/pkg/dataplane"
	"k8s.io/klog/v2"
)

// ParseDataplaneFlags is the function to get the required config structure from passed flags
func ParseDataplaneFlags() (bool, *dataplane.Configuration, error) {

	var (
		flags       = pflag.NewFlagSet("", pflag.ExitOnError)
		grpcAddress = flags.String("grpc-host", "ingress-nginx:10000", "Address to connect to gRPC Control plane")

		showVersion = flags.Bool("version", false,
			`Show release information about the NGINX Ingress controller and exit.`)

		// Ports:
		httpPort      = flags.Int("http-port", 80, `Port to use for servicing HTTP traffic.`)
		httpsPort     = flags.Int("https-port", 443, `Port to use for servicing HTTPS traffic.`)
		sslProxyPort  = flags.Int("ssl-passthrough-proxy-port", 442, `Port to use internally for SSL Passthrough.`)
		defServerPort = flags.Int("default-server-port", 8181, `Port to use for exposing the default server (catch-all).`)
		healthzPort   = flags.Int("healthz-port", 10254, "Port to use for the healthz endpoint.")

		/*healthzPort = flags.Int("healthz-port", 10254, "Port to use for the healthz endpoint.")
		healthzHost = flags.String("healthz-host", "", "Address to bind the healthz endpoint.")*/
	)

	flags.Parse(os.Args)

	// Workaround for this issue:
	// https://github.com/kubernetes/kubernetes/issues/17162
	flag.CommandLine.Parse([]string{})

	pflag.VisitAll(func(flag *pflag.Flag) {
		klog.V(2).InfoS("FLAG", flag.Name, flag.Value)
	})

	if *showVersion {
		return true, nil, nil
	}

	var err error
	config := &dataplane.Configuration{
		GRPCAddress: *grpcAddress,
		ListenPorts: &ngx_config.ListenPorts{
			Default:  *defServerPort,
			Health:   *healthzPort,
			HTTP:     *httpPort,
			HTTPS:    *httpsPort,
			SSLProxy: *sslProxyPort,
		},
	}
	return false, config, err
}