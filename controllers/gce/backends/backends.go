/*
Copyright 2015 The Kubernetes Authors.

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

package backends

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/golang/glog"

	compute "google.golang.org/api/compute/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	api_v1 "k8s.io/client-go/pkg/api/v1"

	"k8s.io/ingress/controllers/gce/healthchecks"
	"k8s.io/ingress/controllers/gce/instances"
	"k8s.io/ingress/controllers/gce/storage"
	"k8s.io/ingress/controllers/gce/utils"
)

// BalancingMode represents the loadbalancing configuration of an individual
// Backend in a BackendService. This is *effectively* a cluster wide setting
// since you can't mix modes across Backends pointing to the same IG, and you
// can't have a single node in more than 1 loadbalanced IG.
type BalancingMode string

const (
	// Rate balances incoming requests based on observed RPS.
	// As of this writing, it's the only balancing mode supported by GCE's
	// internal LB. This setting doesn't make sense for Kubernets clusters
	// because requests can get proxied between instance groups in different
	// zones by kube-proxy without GCE even knowing it. Setting equal RPS on
	// all IGs should achieve roughly equal distribution of requests.
	Rate BalancingMode = "RATE"
	// Utilization balances incoming requests based on observed utilization.
	// This mode is only useful if you want to divert traffic away from IGs
	// running other compute intensive workloads. Utilization statistics are
	// aggregated per instances, not per container, and requests can get proxied
	// between instance groups in different zones by kube-proxy without GCE even
	// knowing about it.
	Utilization BalancingMode = "UTILIZATION"
	// Connections balances incoming requests based on a connection counter.
	// This setting currently doesn't make sense for Kubernetes clusters,
	// because we use NodePort Services as HTTP LB backends, so GCE's connection
	// counters don't accurately represent connections per container.
	Connections BalancingMode = "CONNECTION"
)

// maxRPS is the RPS setting for all Backends with BalancingMode RATE. The exact
// value doesn't matter, as long as it's the same for all Backends. Requests
// received by GCLB above this RPS are NOT dropped, GCLB continues to distribute
// them across IGs.
// TODO: Should this be math.MaxInt64?
const maxRPS = 1

// Backends implements BackendPool.
type Backends struct {
	cloud         BackendServices
	nodePool      instances.NodePool
	healthChecker healthchecks.HealthChecker
	snapshotter   storage.Snapshotter
	prober        probeProvider
	// ignoredPorts are a set of ports excluded from GC, even
	// after the Ingress has been deleted. Note that invoking
	// a Delete() on these ports will still delete the backend.
	ignoredPorts sets.String
	namer        *utils.Namer
}

func portKey(port int64) string {
	return fmt.Sprintf("%d", port)
}

// ServicePort for tupling port and protocol
type ServicePort struct {
	Port     int64
	Protocol utils.AppProtocol
}

// NewBackendPool returns a new backend pool.
// - cloud: implements BackendServices and syncs backends with a cloud provider
// - healthChecker: is capable of producing health checks for backends.
// - nodePool: implements NodePool, used to create/delete new instance groups.
// - namer: procudes names for backends.
// - ignorePorts: is a set of ports to avoid syncing/GCing.
// - resyncWithCloud: if true, periodically syncs with cloud resources.
func NewBackendPool(
	cloud BackendServices,
	healthChecker healthchecks.HealthChecker,
	nodePool instances.NodePool,
	namer *utils.Namer,
	ignorePorts []int64,
	resyncWithCloud bool) *Backends {

	ignored := []string{}
	for _, p := range ignorePorts {
		ignored = append(ignored, portKey(p))
	}
	backendPool := &Backends{
		cloud:         cloud,
		nodePool:      nodePool,
		healthChecker: healthChecker,
		namer:         namer,
		ignoredPorts:  sets.NewString(ignored...),
	}
	if !resyncWithCloud {
		backendPool.snapshotter = storage.NewInMemoryPool()
		return backendPool
	}
	backendPool.snapshotter = storage.NewCloudListingPool(
		func(i interface{}) (string, error) {
			bs := i.(*compute.BackendService)
			if !namer.NameBelongsToCluster(bs.Name) {
				return "", fmt.Errorf("unrecognized name %v", bs.Name)
			}
			port, err := namer.BePort(bs.Name)
			if err != nil {
				return "", err
			}
			return port, nil
		},
		backendPool,
		30*time.Second,
	)
	return backendPool
}

// Init sets the probeProvider interface value
func (b *Backends) Init(pp probeProvider) {
	b.prober = pp
}

// Get returns a single backend.
func (b *Backends) Get(port int64) (*compute.BackendService, error) {
	be, err := b.cloud.GetBackendService(b.namer.BeName(port))
	if err != nil {
		return nil, err
	}
	b.snapshotter.Add(portKey(port), be)
	return be, nil
}

func (b *Backends) ensureHealthCheck(port int64, protocol utils.AppProtocol) (string, error) {
	hc := b.healthChecker.New(port, protocol)
	if b.prober != nil {
		probe, err := b.prober.GetProbe(port)
		if err != nil {
			return "", err
		}
		if probe != nil {
			glog.Infof("Applying httpGet settings of readinessProbe to health check on port %v", port)
			applyProbeSettingsToHC(probe, hc)
		}
	}

	return b.healthChecker.Sync(hc)
}

func (b *Backends) create(igs []*compute.InstanceGroup, namedPort *compute.NamedPort, hcLink string, protocol utils.AppProtocol, name string) (*compute.BackendService, error) {
	var errs []string
	// We first try to create the backend with balancingMode=RATE.  If this
	// fails, it's mostly likely because there are existing backends with
	// balancingMode=UTILIZATION. This failure mode throws a googleapi error
	// which wraps a HTTP 400 status code. We handle it in the loop below
	// and come around to retry with the right balancing mode. The goal is to
	// switch everyone to using RATE.
	for _, bm := range []BalancingMode{Rate, Utilization} {
		// Create a new backend
		bs := newBackendService(igs, bm, namedPort, []string{hcLink}, protocol, name)
		if err := b.cloud.CreateBackendService(bs); err != nil {
			// This is probably a failure because we tried to create the backend
			// with balancingMode=RATE when there are already backends with
			// balancingMode=UTILIZATION. Just ignore it and retry setting
			// balancingMode=UTILIZATION (b/35102911).
			if utils.IsHTTPErrorCode(err, http.StatusBadRequest) {
				glog.Infof("Error creating backend service with balancing mode %v:%v", bm, err)
				errs = append(errs, fmt.Sprintf("%v", err))
				continue
			}
			return nil, err
		}
		return b.Get(namedPort.Port)
	}
	return nil, fmt.Errorf("%v", strings.Join(errs, "\n"))
}

func newBackendService(igs []*compute.InstanceGroup, bm BalancingMode, namedPort *compute.NamedPort, healthCheckLinks []string, protocol utils.AppProtocol, name string) *compute.BackendService {
	backends := getBackendsForIGs(igs)
	for _, b := range backends {
		switch bm {
		case Rate:
			b.MaxRatePerInstance = maxRPS
		default:
			// TODO: Set utilization and connection limits when we accept them
			// as valid fields.
		}
		b.BalancingMode = string(bm)
	}

	return &compute.BackendService{
		Name:         name,
		Protocol:     string(protocol),
		Backends:     backends,
		HealthChecks: healthCheckLinks,
		Port:         namedPort.Port,
		PortName:     namedPort.Name,
	}
}

// Add will get or create a Backend for the given port.
func (b *Backends) Add(p ServicePort) error {
	// We must track the port even if creating the backend failed, because
	// we might've created a health-check for it.
	be := &compute.BackendService{}
	defer func() { b.snapshotter.Add(portKey(p.Port), be) }()

	igs, namedPort, err := b.nodePool.AddInstanceGroup(b.namer.IGName(), p.Port)
	if err != nil {
		return err
	}

	// Ensure health check for backend service exists
	hcLink, err := b.ensureHealthCheck(p.Port, p.Protocol)
	if err != nil {
		return err
	}

	pName := b.namer.BeName(p.Port)
	be, _ = b.Get(p.Port)
	if be == nil {
		glog.Infof("Creating backend for %d instance groups, port %v named port %v", len(igs), p.Port, namedPort)
		be, err = b.create(igs, namedPort, hcLink, p.Protocol, pName)
		if err != nil {
			return err
		}
	}

	existingHCLink := ""
	if len(be.HealthChecks) == 1 {
		existingHCLink = be.HealthChecks[0]
	}

	if be.Protocol != string(p.Protocol) || existingHCLink != hcLink {
		glog.Infof("Updating backend protocol %v (%v) for change in protocol (%v) or health check", pName, be.Protocol, string(p.Protocol))
		be.Protocol = string(p.Protocol)
		be.HealthChecks = []string{hcLink}
		if err = b.cloud.UpdateBackendService(be); err != nil {
			return err
		}
	}

	// If previous health check was legacy type, we need to delete it.
	if existingHCLink != hcLink && strings.Contains(existingHCLink, "/httpHealthChecks/") {
		if err = b.healthChecker.DeleteLegacy(p.Port); err != nil {
			return err
		}
	}

	// we won't find any igs till the node pool syncs nodes.
	if len(igs) == 0 {
		return nil
	}
	if err = b.edgeHop(be, igs); err != nil {
		return err
	}
	return err
}

// Delete deletes the Backend for the given port.
func (b *Backends) Delete(port int64) (err error) {
	name := b.namer.BeName(port)
	glog.Infof("Deleting backend service %v", name)
	defer func() {
		if utils.IsHTTPErrorCode(err, http.StatusNotFound) {
			err = nil
		}
		if err == nil {
			b.snapshotter.Delete(portKey(port))
		}
	}()
	// Try deleting health checks even if a backend is not found.
	if err = b.cloud.DeleteBackendService(name); err != nil && !utils.IsHTTPErrorCode(err, http.StatusNotFound) {
		return err
	}

	return b.healthChecker.Delete(port)
}

// List lists all backends.
func (b *Backends) List() ([]interface{}, error) {
	// TODO: for consistency with the rest of this sub-package this method
	// should return a list of backend ports.
	interList := []interface{}{}
	be, err := b.cloud.ListBackendServices()
	if err != nil {
		return interList, err
	}
	for i := range be.Items {
		interList = append(interList, be.Items[i])
	}
	return interList, nil
}

func getBackendsForIGs(igs []*compute.InstanceGroup) []*compute.Backend {
	backends := []*compute.Backend{}
	for _, ig := range igs {
		backends = append(backends, &compute.Backend{Group: ig.SelfLink})
	}
	return backends
}

// edgeHop checks the links of the given backend by executing an edge hop.
// It fixes broken links.
func (b *Backends) edgeHop(be *compute.BackendService, igs []*compute.InstanceGroup) error {
	beIGs := sets.String{}
	for _, beToIG := range be.Backends {
		beIGs.Insert(beToIG.Group)
	}
	igLinks := sets.String{}
	for _, igToBE := range igs {
		igLinks.Insert(igToBE.SelfLink)
	}
	if beIGs.IsSuperset(igLinks) {
		return nil
	}
	glog.Infof("Backend %v has a broken edge, expected igs %+v, current igs %+v",
		be.Name, igLinks.List(), beIGs.List())

	newBackends := []*compute.Backend{}
	for _, b := range getBackendsForIGs(igs) {
		if !beIGs.Has(b.Group) {
			newBackends = append(newBackends, b)
		}
	}
	be.Backends = append(be.Backends, newBackends...)
	if err := b.cloud.UpdateBackendService(be); err != nil {
		return err
	}
	return nil
}

// Sync syncs backend services corresponding to ports in the given list.
func (b *Backends) Sync(svcNodePorts []ServicePort) error {
	glog.V(3).Infof("Sync: backends %v", svcNodePorts)

	// create backends for new ports, perform an edge hop for existing ports
	for _, port := range svcNodePorts {
		if err := b.Add(port); err != nil {
			return err
		}
	}
	return nil
}

// GC garbage collects services corresponding to ports in the given list.
func (b *Backends) GC(svcNodePorts []ServicePort) error {
	knownPorts := sets.NewString()
	for _, p := range svcNodePorts {
		knownPorts.Insert(portKey(p.Port))
	}
	pool := b.snapshotter.Snapshot()
	for port := range pool {
		p, err := strconv.ParseInt(port, 10, 64)
		if err != nil {
			return err
		}
		nodePort := int64(p)
		if knownPorts.Has(portKey(nodePort)) || b.ignoredPorts.Has(portKey(nodePort)) {
			continue
		}
		glog.V(3).Infof("GCing backend for port %v", p)
		if err := b.Delete(nodePort); err != nil {
			return err
		}
	}
	return nil
}

// Shutdown deletes all backends and the default backend.
// This will fail if one of the backends is being used by another resource.
func (b *Backends) Shutdown() error {
	if err := b.GC([]ServicePort{}); err != nil {
		return err
	}
	return nil
}

// Status returns the status of the given backend by name.
func (b *Backends) Status(name string) string {
	backend, err := b.cloud.GetBackendService(name)
	if err != nil {
		return "Unknown"
	}
	// TODO: Include port, ip in the status, since it's in the health info.
	hs, err := b.cloud.GetHealth(name, backend.Backends[0].Group)
	if err != nil || len(hs.HealthStatus) == 0 || hs.HealthStatus[0] == nil {
		return "Unknown"
	}
	// TODO: State transition are important, not just the latest.
	return hs.HealthStatus[0].HealthState
}

func applyProbeSettingsToHC(p *api_v1.Probe, hc *healthchecks.HealthCheck) {
	healthPath := p.Handler.HTTPGet.Path
	// GCE requires a leading "/" for health check urls.
	if !strings.HasPrefix(healthPath, "/") {
		healthPath = fmt.Sprintf("/%v", healthPath)
	}

	host := p.Handler.HTTPGet.Host
	// remember the ingresses that use this Service so we can send
	// the right events

	hc.RequestPath = healthPath
	hc.Host = host
	hc.Description = "Kubernetes L7 health check generated with readiness probe settings."
	// set a low health threshold and a high failure threshold.
	// We're just trying to detect if the node networking is
	// borked, service level outages will get detected sooner
	// by kube-proxy.
	hc.CheckIntervalSec = int64(p.PeriodSeconds + healthchecks.DefaultHealthCheckInterval)
	hc.TimeoutSec = int64(p.TimeoutSeconds)
}
