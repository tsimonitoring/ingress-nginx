/*
Copyright 2024 The Kubernetes Authors.

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

package crossplane

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	ngx_crossplane "github.com/nginxinc/nginx-go-crossplane"

	"k8s.io/ingress-nginx/internal/ingress/controller/config"
	ing_net "k8s.io/ingress-nginx/internal/net"
	"k8s.io/ingress-nginx/pkg/apis/ingress"
)

type seconds int

func buildDirective(directive string, args ...any) *ngx_crossplane.Directive {
	argsVal := make([]string, 0)
	for k := range args {
		switch v := args[k].(type) {
		case string:
			argsVal = append(argsVal, v)
		case []string:
			argsVal = append(argsVal, v...)
		case int:
			argsVal = append(argsVal, strconv.Itoa(v))
		case bool:
			argsVal = append(argsVal, boolToStr(v))
		case seconds:
			argsVal = append(argsVal, strconv.Itoa(int(v))+"s")
		}
	}
	return &ngx_crossplane.Directive{
		Directive: directive,
		Args:      argsVal,
	}
}

func buildLuaSharedDictionaries(cfg *config.Configuration) []*ngx_crossplane.Directive {
	out := make([]*ngx_crossplane.Directive, 0, len(cfg.LuaSharedDicts))
	for name, size := range cfg.LuaSharedDicts {
		sizeStr := dictKbToStr(size)
		out = append(out, buildDirective("lua_shared_dict", name, sizeStr))
	}

	return out
}

// TODO: The utils below should be moved to a level where they can be consumed by any template writer

// buildResolvers returns the resolvers reading the /etc/resolv.conf file
func buildResolversInternal(res []net.IP, disableIpv6 bool) []string {
	r := make([]string, 0)
	for _, ns := range res {
		if ing_net.IsIPV6(ns) {
			if disableIpv6 {
				continue
			}
			r = append(r, fmt.Sprintf("[%s]", ns))
		} else {
			r = append(r, ns.String())
		}
	}
	r = append(r, "valid=30s")

	if disableIpv6 {
		r = append(r, "ipv6=off")
	}

	return r
}

// buildBlockDirective is used to build a block directive
func buildBlockDirective(blockName string, args []string, block ngx_crossplane.Directives) *ngx_crossplane.Directive {
	return &ngx_crossplane.Directive{
		Directive: blockName,
		Args:      args,
		Block:     block,
	}
}

// buildMapDirective is used to build a map directive
func buildMapDirective(name, variable string, block ngx_crossplane.Directives) *ngx_crossplane.Directive {
	return buildBlockDirective("map", []string{name, variable}, block)
}

func boolToStr(b bool) string {
	if b {
		return "on"
	}
	return "off"
}

func dictKbToStr(size int) string {
	if size%1024 == 0 {
		return fmt.Sprintf("%dM", size/1024)
	}
	return fmt.Sprintf("%dK", size)
}

func shouldLoadAuthDigestModule(servers []*ingress.Server) bool {
	for _, server := range servers {
		for _, location := range server.Locations {
			if !location.BasicDigestAuth.Secured {
				continue
			}

			if location.BasicDigestAuth.Type == "digest" {
				return true
			}
		}
	}
	return false
}

// shouldLoadOpentelemetryModule determines whether or not the Opentelemetry module needs to be loaded.
// It checks if `enable-opentelemetry` is set in the ConfigMap.
func shouldLoadOpentelemetryModule(servers []*ingress.Server) bool {
	for _, server := range servers {
		for _, location := range server.Locations {
			if location.Opentelemetry.Enabled {
				return true
			}
		}
	}
	return false
}

func buildServerName(hostname string) string {
	if !strings.HasPrefix(hostname, "*") {
		return hostname
	}

	hostname = strings.Replace(hostname, "*.", "", 1)
	parts := strings.Split(hostname, ".")

	return `~^(?<subdomain>[\w-]+)\.` + strings.Join(parts, "\\.") + `$`
}

func buildListener(tc config.TemplateConfig, hostname string) ngx_crossplane.Directives {
	listenDirectives := make(ngx_crossplane.Directives, 0)

	co := commonListenOptions(&tc, hostname)

	addrV4 := []string{""}
	if len(tc.Cfg.BindAddressIpv4) > 0 {
		addrV4 = tc.Cfg.BindAddressIpv4
	}
	listenDirectives = append(listenDirectives, httpListener(addrV4, co, &tc, false)...)
	listenDirectives = append(listenDirectives, httpListener(addrV4, co, &tc, true)...)

	if tc.IsIPV6Enabled {
		addrV6 := []string{"[::]"}
		if len(tc.Cfg.BindAddressIpv6) > 0 {
			addrV6 = tc.Cfg.BindAddressIpv6
		}
		listenDirectives = append(listenDirectives, httpListener(addrV6, co, &tc, false)...)
		listenDirectives = append(listenDirectives, httpListener(addrV6, co, &tc, true)...)
	}

	return listenDirectives
}

// commonListenOptions defines the common directives that should be added to NGINX listeners
func commonListenOptions(template *config.TemplateConfig, hostname string) []string {
	var out []string

	if template.Cfg.UseProxyProtocol {
		out = append(out, "proxy_protocol")
	}

	if hostname != "_" {
		return out
	}

	out = append(out, "default_server")

	if template.Cfg.ReusePort {
		out = append(out, "reuseport")
	}
	out = append(out, fmt.Sprintf("backlog=%d", template.BacklogSize))
	return out
}

func httpListener(addresses []string, co []string, tc *config.TemplateConfig, ssl bool) ngx_crossplane.Directives {
	listeners := make(ngx_crossplane.Directives, 0)
	port := tc.ListenPorts.HTTP
	isTLSProxy := tc.IsSSLPassthroughEnabled
	// If this is a SSL listener we should mutate the port properly
	if ssl {
		port = tc.ListenPorts.HTTPS
		if isTLSProxy {
			port = tc.ListenPorts.SSLProxy
		}
	}
	for _, address := range addresses {
		var listenAddress string
		if address == "" {
			listenAddress = fmt.Sprintf("%d", port)
		} else {
			listenAddress = fmt.Sprintf("%s:%d", address, port)
		}
		if ssl {
			if isTLSProxy {
				co = append(co, "proxy_protocol")
			}
			co = append(co, "ssl")
		}
		listenDirective := buildDirective("listen", listenAddress, co)
		listeners = append(listeners, listenDirective)
	}

	return listeners
}
