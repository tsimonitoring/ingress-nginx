/*
Copyright 2016 The Kubernetes Authors.

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

package connection

import (
	"regexp"

	networking "k8s.io/api/networking/v1"

	"k8s.io/ingress-nginx/internal/ingress/annotations/parser"
	"k8s.io/ingress-nginx/internal/ingress/resolver"
)

const (
	connectionProxyHeaderAnnotation = "connection-proxy-header"
)

var (
	validConnectionHeaderValue = regexp.MustCompile(`^(close|keep-alive)$`)
)

var connectionHeadersAnnotations = parser.Annotation{
	Group: "backend",
	Annotations: parser.AnnotationFields{
		connectionProxyHeaderAnnotation: {
			Validator:     parser.ValidateRegex(*validConnectionHeaderValue, true),
			Scope:         parser.AnnotationScopeLocation,
			Risk:          parser.AnnotationRiskLow,
			Documentation: `This annotation allows setting a specific value for "proxy_set_header Connection" directive. Right now it is restricted to "close" or "keep-alive"`,
		},
	},
}

// Config returns the connection header configuration for an Ingress rule
type Config struct {
	Header  string `json:"header"`
	Enabled bool   `json:"enabled"`
}

type connection struct {
	r                resolver.Resolver
	annotationConfig parser.Annotation
}

// NewParser creates a new port in redirect annotation parser
func NewParser(r resolver.Resolver) parser.IngressAnnotation {
	return connection{
		r:                r,
		annotationConfig: connectionHeadersAnnotations,
	}
}

// Parse parses the annotations contained in the ingress
// rule used to indicate if the connection header should be overridden.
func (a connection) Parse(ing *networking.Ingress) (interface{}, error) {
	cp, err := parser.GetStringAnnotation(connectionProxyHeaderAnnotation, ing, a.annotationConfig.Annotations)
	if err != nil {
		return &Config{
			Enabled: false,
		}, err
	}
	return &Config{
		Enabled: true,
		Header:  cp,
	}, nil
}

// Equal tests for equality between two Connection types
func (r1 *Config) Equal(r2 *Config) bool {
	if r1 == r2 {
		return true
	}
	if r1 == nil || r2 == nil {
		return false
	}
	if r1.Enabled != r2.Enabled {
		return false
	}
	if r1.Header != r2.Header {
		return false
	}

	return true
}

func (a connection) GetDocumentation() parser.AnnotationFields {
	return a.annotationConfig.Annotations
}

func (a connection) Validate(anns map[string]string) error {
	maxrisk := parser.StringRiskToRisk(a.r.GetSecurityConfiguration().AnnotationsRisk)
	return parser.CheckAnnotationRisk(anns, maxrisk, connectionHeadersAnnotations.Annotations)
}