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
	"strings"

	ngx_crossplane "github.com/nginxinc/nginx-go-crossplane"
	"k8s.io/ingress-nginx/internal/ingress/annotations/authreq"
	"k8s.io/ingress-nginx/internal/ingress/controller/config"
	"k8s.io/ingress-nginx/pkg/apis/ingress"
)

type externalAuth struct {
	AuthCacheKey           string            `json:"authCacheKey"`
	AuthCacheDuration      []string          `json:"authCacheDuration"`
	Method                 string            `json:"method"`
	Host                   string            `json:"host"`
	RequestRedirect        string            `json:"requestRedirect"`
	ProxySetHeaders        map[string]string `json:"proxySetHeaders,omitempty"`
	URL                    string            `json:"url"`
	SigninURL              string            `json:"signinUrl"`
	SigninURLRedirectParam string            `json:"signinUrlRedirectParam"`
}

func buildExternalAuth(cfg any) *externalAuth {
	switch v := cfg.(type) {
	case config.GlobalExternalAuth:
		return &externalAuth{
			AuthCacheKey:           v.AuthCacheKey,
			AuthCacheDuration:      v.AuthCacheDuration,
			Method:                 v.Method,
			Host:                   v.Host,
			RequestRedirect:        v.RequestRedirect,
			ProxySetHeaders:        v.ProxySetHeaders,
			URL:                    v.URL,
			SigninURL:              v.SigninURL,
			SigninURLRedirectParam: v.SigninURLRedirectParam,
		}
	case authreq.Config:
		return &externalAuth{
			AuthCacheKey:           v.AuthCacheKey,
			AuthCacheDuration:      v.AuthCacheDuration,
			Method:                 v.Method,
			Host:                   v.Host,
			RequestRedirect:        v.RequestRedirect,
			ProxySetHeaders:        v.ProxySetHeaders,
			URL:                    v.URL,
			SigninURL:              v.SigninURL,
			SigninURLRedirectParam: v.SigninURLRedirectParam,
		}
	default:
		return nil
	}
}

func (c *Template) buildAuthLocation(server *ingress.Server,
	location *ingress.Location, authPath string,
	externalA *externalAuth, applyAuthUpstream bool, applyGlobalAuth bool) *ngx_crossplane.Directive {
	locationDirectives := ngx_crossplane.Directives{
		buildDirective("internal"),
	}

	if c.tplConfig.Cfg.EnableOpentelemetry || location.Opentelemetry.Enabled {
		locationDirectives = append(locationDirectives,
			buildDirective("opentelemetry", "on"),
			buildDirective("opentelemetry_propagate"),
		)
	}

	if !c.tplConfig.Cfg.EnableAuthAccessLog {
		locationDirectives = append(locationDirectives, buildDirective("access_log", "off"))
	}

	if externalA.AuthCacheKey != "" {
		locationDirectives = append(locationDirectives,
			buildDirective("set", "$tmp_cache_key", fmt.Sprintf("%s%s%s", server.Hostname, authPath, externalA.AuthCacheKey)),
			buildDirective("set", "$cache_key", ""),
			buildDirective("rewrite_by_lua_file", "/etc/nginx/lua/nginx/ngx_conf_rewrite_auth.lua"),
			buildDirective("proxy_cache", "auth_cache"),
			buildDirective("proxy_cache_key", "$cache_key"),
		)
		for i := range externalA.AuthCacheDuration {
			locationDirectives = append(locationDirectives,
				buildDirective("proxy_cache_valid", strings.Split(externalA.AuthCacheDuration[i], " ")),
			)
		}
	}

	/*
		ngx_auth_request module overrides variables in the parent request,
		therefore we have to explicitly set this variable again so that when the parent request
		resumes it has the correct value set for this variable so that Lua can pick backend correctly
	*/
	locationDirectives = append(locationDirectives,
		buildDirective("set", "$proxy_upstream_name", location.Backend),
	)

	locationDirectives = append(locationDirectives,
		buildDirective("proxy_pass_request_body", "off"))

	locationDirectives = append(locationDirectives,
		buildDirective("proxy_ssl_server_name", "on"))
	locationDirectives = append(locationDirectives,
		buildDirective("proxy_pass_request_headers", "on"))

	locationDirectives = append(locationDirectives,
		buildDirective("proxy_set_header", "Content-Length", ""))
	locationDirectives = append(locationDirectives,
		buildDirective("proxy_set_header", "X-Forwarded-Proto", ""))
	locationDirectives = append(locationDirectives,
		buildDirective("proxy_set_header", "X-Request-ID", "$req_id"))
	locationDirectives = append(locationDirectives,
		buildDirective("proxy_set_header", "Host", externalA.Host))
	locationDirectives = append(locationDirectives,
		buildDirective("proxy_set_header", "X-Original-URL", "$scheme://$http_host$request_uri"))
	locationDirectives = append(locationDirectives,
		buildDirective("proxy_set_header", "X-Original-Method", "$request_method"))
	locationDirectives = append(locationDirectives,
		buildDirective("proxy_set_header", "X-Sent-From", "nginx-ingress-controller"))
	locationDirectives = append(locationDirectives,
		buildDirective("proxy_set_header", "X-Real-IP", "$remote_addr"))

	if c.tplConfig.Cfg.UseForwardedHeaders && c.tplConfig.Cfg.ComputeFullForwardedFor {
		locationDirectives = append(locationDirectives,
			buildDirective("proxy_set_header", "X-Forwarded-For", "$full_x_forwarded_for"))
	} else {
		locationDirectives = append(locationDirectives,
			buildDirective("proxy_set_header", "X-Forwarded-For", "$remote_addr"))
	}

	if externalA.RequestRedirect != "" {
		locationDirectives = append(locationDirectives,
			buildDirective("proxy_set_header", "X-Auth-Request-Redirect", externalA.RequestRedirect))
	} else {
		locationDirectives = append(locationDirectives,
			buildDirective("proxy_set_header", "X-Auth-Request-Redirect", "$request_uri"))
	}

	if externalA.Method != "" {
		locationDirectives = append(locationDirectives,
			buildDirective("proxy_set_header", "X-Original-URI", "$request_uri"))
		locationDirectives = append(locationDirectives,
			buildDirective("proxy_set_header", "X-Scheme", "$pass_access_scheme"))
	}

	if externalA.AuthCacheKey != "" {
		locationDirectives = append(locationDirectives,
			buildDirective("proxy_buffering", "on"))
	} else {
		locationDirectives = append(locationDirectives,
			buildDirective("proxy_buffering", location.Proxy.ProxyBuffering))
	}

	locationDirectives = append(locationDirectives,
		buildDirective("proxy_buffer_size", location.Proxy.BufferSize))
	locationDirectives = append(locationDirectives,
		buildDirective("proxy_buffers", location.Proxy.BuffersNumber, location.Proxy.BufferSize))
	locationDirectives = append(locationDirectives,
		buildDirective("proxy_request_buffering", location.Proxy.RequestBuffering))

	if isValidByteSize(location.Proxy.BodySize, true) {
		locationDirectives = append(locationDirectives,
			buildDirective("client_max_body_size", location.Proxy.BodySize))
	}

	if isValidByteSize(location.ClientBodyBufferSize, false) {
		locationDirectives = append(locationDirectives,
			buildDirective("client_body_buffer_size", location.ClientBodyBufferSize))
	}

	if server.CertificateAuth.CAFileName != "" {
		locationDirectives = append(locationDirectives,
			buildDirective("proxy_set_header", "ssl-client-verify", "$ssl_client_verify"))

		locationDirectives = append(locationDirectives,
			buildDirective("proxy_set_header", "ssl-client-subject-dn", "$ssl_client_s_dn"))

		locationDirectives = append(locationDirectives,
			buildDirective("proxy_set_header", "ssl-client-issuer-dn", "$ssl_client_i_dn"))

		if server.CertificateAuth.PassCertToUpstream {
			locationDirectives = append(locationDirectives,
				buildDirective("proxy_set_header", "ssl-client-cert", "$ssl_client_escaped_cert"))
		}
	}

	for name, value := range externalA.ProxySetHeaders {
		locationDirectives = append(locationDirectives,
			buildDirective("proxy_set_header", name, value))
	}

	if applyAuthUpstream && applyGlobalAuth {
		locationDirectives = append(locationDirectives,
			buildDirective("proxy_http_version", "1.1"))
		locationDirectives = append(locationDirectives,
			buildDirective("proxy_set_header", "Connection", ""))
		locationDirectives = append(locationDirectives,
			buildDirective("set", "$target",
				changeHostPort(externalA.URL, buildAuthUpstreamName(location, server.Hostname))))
	} else {
		locationDirectives = append(locationDirectives,
			buildDirective("proxy_http_version", location.Proxy.ProxyHTTPVersion))
		locationDirectives = append(locationDirectives,
			buildDirective("set", "$target", externalA.URL))
	}
	locationDirectives = append(locationDirectives,
		buildDirective("proxy_pass", "$target"))

	return buildBlockDirective("location",
		[]string{"=", authPath}, locationDirectives)
}
