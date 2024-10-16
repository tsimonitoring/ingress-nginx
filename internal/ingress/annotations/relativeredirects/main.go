/*
Copyright 2023 The Kubernetes Authors.

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

package relativeredirects

import (
	networking "k8s.io/api/networking/v1"

	goErrors "errors"

	"k8s.io/ingress-nginx/internal/ingress/annotations/parser"
	"k8s.io/ingress-nginx/internal/ingress/errors"
	"k8s.io/ingress-nginx/internal/ingress/resolver"
)

const (
	relativeRedirectsAnnotation = "relative-redirects"
)

var relativeRedirectsAnnotations = parser.Annotation{
	Group: "redirect",
	Annotations: parser.AnnotationFields{
		relativeRedirectsAnnotation: {
			Validator:     parser.ValidateBool,
			Scope:         parser.AnnotationScopeLocation,
			Risk:          parser.AnnotationRiskLow,
			Documentation: `If enabled, redirects issued by nginx will be relative. See https://nginx.org/en/docs/http/ngx_http_core_module.html#absolute_redirect`,
		},
	},
}

type relativeRedirect struct {
	r                resolver.Resolver
	annotationConfig parser.Annotation
}

func (ar relativeRedirect) GetDocumentation() parser.AnnotationFields {
	return ar.annotationConfig.Annotations
}

func (ar relativeRedirect) Validate(anns map[string]string) error {
	maxrisk := parser.StringRiskToRisk(ar.r.GetSecurityConfiguration().AnnotationsRiskLevel)
	return parser.CheckAnnotationRisk(anns, maxrisk, relativeRedirectsAnnotations.Annotations)
}

// NewParser creates a new relativeRedirects annotation parser
func NewParser(r resolver.Resolver) parser.IngressAnnotation {
	return relativeRedirect{
		r:                r,
		annotationConfig: relativeRedirectsAnnotations,
	}
}

func (ar relativeRedirect) Parse(ing *networking.Ingress) (interface{}, error) {
	val, err := parser.GetBoolAnnotation(relativeRedirectsAnnotation, ing, ar.annotationConfig.Annotations)

	// A missing annotation is not a problem, just use the default which is `absolute_redirects on`
	if goErrors.Is(err, errors.ErrMissingAnnotations) {
		return false, nil // default is false
	}

	return val, nil
}
