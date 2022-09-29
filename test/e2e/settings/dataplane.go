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

package settings

import (
	"strings"

	"github.com/onsi/ginkgo/v2"
	"k8s.io/ingress-nginx/test/e2e/framework"
)

/* This test will check if gRPC flag is set in control plane, it should not enable
NGINX service but still, the controller process should be up and running and responsive */

var _ = framework.IngressNginxDescribe("[Flag] grpc-port", func() {

	f := framework.NewDefaultFramework("grpc-port")

	ginkgo.BeforeEach(func() {
		f.NewEchoDeployment()
	})

	ginkgo.Context("Disable local nginx with grpc enabled", func() {
		ginkgo.It("should reconfigure nginx.conf but skip the server", func() {
			//ginkgo.Skip("skipping for now")

			host := "test.grpc"

			ing := framework.NewSingleIngress("exact", "/bbb", host, f.Namespace, framework.EchoService, 80, nil)
			f.EnsureIngress(ing)

			f.WaitForNginxServer(host,
				func(server string) bool {
					return strings.Contains(server, host) &&
						strings.Contains(server, "location /bbb")
				})

			f.HTTPTestClient().
				GET("/").
				WithHeader("Host", host).
				ExpectFail()

		})
	})
})