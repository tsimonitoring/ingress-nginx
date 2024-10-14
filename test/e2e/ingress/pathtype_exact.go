/*
Copyright 2019 The Kubernetes Authors.

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

package ingress

import (
	"net/http"
	"strings"

	"github.com/onsi/ginkgo/v2"
	"github.com/stretchr/testify/assert"
	networking "k8s.io/api/networking/v1"

	"k8s.io/ingress-nginx/test/e2e/framework"
)

var _ = framework.IngressNginxDescribe("[Ingress] [PathType] exact", func() {
	f := framework.NewDefaultFramework("exact")

	ginkgo.BeforeEach(func() {
		f.NewEchoDeployment()
	})

	ginkgo.It("should choose exact location for /exact", func() {

		f.UpdateNginxConfigMapData("global-allowed-response-headers", "pathtype,duplicated")

		annotations := map[string]string{
			"nginx.ingress.kubernetes.io/custom-headers": f.Namespace + "/custom-headers-exact",
		}

		f.CreateConfigMap("custom-headers-exact", map[string]string{
			"pathtype": "exact",
		})

		host := "exact.path"
		exactPathType := networking.PathTypeExact
		ing := framework.NewSingleIngress("exact", "/exact", host, f.Namespace, framework.EchoService, 80, annotations)
		ing.Spec.Rules[0].IngressRuleValue.HTTP.Paths[0].PathType = &exactPathType
		f.EnsureIngress(ing)

		annotations = map[string]string{
			"nginx.ingress.kubernetes.io/custom-headers": f.Namespace + "/custom-headers-prefix",
		}

		f.CreateConfigMap("custom-headers-prefix", map[string]string{
			"pathtype": "prefix",
		})

		ing = framework.NewSingleIngress("exact-suffix", "/exact", host, f.Namespace, framework.EchoService, 80, annotations)
		f.EnsureIngress(ing)

		f.WaitForNginxServer(host,
			func(server string) bool {
				return strings.Contains(server, host) &&
					strings.Contains(server, "location = /exact") &&
					strings.Contains(server, "location /exact/")
			})

		body := f.HTTPTestClient().
			GET("/exact").
			WithHeader("Host", host).
			Expect().
			Status(http.StatusOK).
			Body().
			Raw()

		assert.NotContains(ginkgo.GinkgoT(), body, "pathtype=prefix")
		assert.Contains(ginkgo.GinkgoT(), body, "pathtype=exact")

		body = f.HTTPTestClient().
			GET("/exact/suffix").
			WithHeader("Host", host).
			Expect().
			Status(http.StatusOK).
			Body().
			Raw()

		assert.Contains(ginkgo.GinkgoT(), body, "pathtype=prefix")

		annotations = map[string]string{
			"nginx.ingress.kubernetes.io/custom-headers": f.Namespace + "/custom-headers-duplicated",
		}

		f.CreateConfigMap("custom-headers-duplicated", map[string]string{
			"pathtype":   "prefix",
			"duplicated": "true",
		})

		ing = framework.NewSingleIngress("duplicated-prefix", "/exact", host, f.Namespace, framework.EchoService, 80, annotations)
		f.EnsureIngress(ing)

		f.WaitForNginxServer(host,
			func(server string) bool {
				return strings.Contains(server, host) &&
					strings.Contains(server, "location = /exact") &&
					strings.Contains(server, "location /exact/")
			})

		body = f.HTTPTestClient().
			GET("/exact/suffix").
			WithHeader("Host", host).
			Expect().
			Status(http.StatusOK).
			Body().
			Raw()

		assert.Contains(ginkgo.GinkgoT(), body, "pathtype=prefix")
		assert.NotContains(ginkgo.GinkgoT(), body, "pathtype=exact")
		assert.NotContains(ginkgo.GinkgoT(), body, "duplicated=true")
	})
})
