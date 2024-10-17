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

/**
 * Copyright (c) F5, Inc.
 *
 * This source code is licensed under the Apache License, Version 2.0 license found in the
 * LICENSE file in the root directory of this source tree.
 */

// Code generated by generator; DO NOT EDIT.
// All the definitions are extracted from the source code
// Each bit mask describes these behaviors:
//   - how many arguments the directive can take
//   - whether or not it is a block directive
//   - whether this is a flag (takes one argument that's either "on" or "off")
//   - which contexts it's allowed to be in

package extramodules

var opentelemetryDirectives = map[string][]uint{
    "opentelemetry": {
        ngxHTTPMainConf | ngxHTTPSrvConf | ngxHTTPLocConf | ngxConfTake1,
    },
    "opentelemetry_attribute": {
        ngxHTTPMainConf | ngxHTTPSrvConf | ngxHTTPLocConf | ngxConfTake2,
    },
    "opentelemetry_capture_headers": {
        ngxHTTPMainConf | ngxHTTPSrvConf | ngxHTTPLocConf | ngxConfTake1,
    },
    "opentelemetry_config": {
        ngxHTTPMainConf | ngxConfTake1,
    },
    "opentelemetry_ignore_paths": {
        ngxHTTPMainConf | ngxHTTPSrvConf | ngxHTTPLocConf | ngxConfTake1,
    },
    "opentelemetry_operation_name": {
        ngxHTTPMainConf | ngxHTTPSrvConf | ngxHTTPLocConf | ngxConfTake1,
    },
    "opentelemetry_propagate": {
        ngxHTTPMainConf | ngxHTTPSrvConf | ngxHTTPLocConf | ngxConfNoArgs | ngxConfTake1,
    },
    "opentelemetry_sensitive_header_names": {
        ngxHTTPMainConf | ngxHTTPSrvConf | ngxHTTPLocConf | ngxConfTake1,
    },
    "opentelemetry_sensitive_header_values": {
        ngxHTTPMainConf | ngxHTTPSrvConf | ngxHTTPLocConf | ngxConfTake1,
    },
    "opentelemetry_trust_incoming_spans": {
        ngxHTTPMainConf | ngxHTTPSrvConf | ngxHTTPLocConf | ngxConfTake1,
    },
}


func OpentelemetryMatchFn(directive string) ([]uint, bool) {
    m, ok := opentelemetryDirectives[directive]
    return m, ok
}
