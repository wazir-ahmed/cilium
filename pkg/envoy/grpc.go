// Copyright 2018 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package envoy

import (
	"context"
	"errors"
	"net"
	"time"

	"github.com/cilium/cilium/pkg/envoy/xds"

	cilium "github.com/cilium/proxy/go/cilium/api"
	envoy_service_discovery "github.com/cilium/proxy/go/envoy/service/discovery/v3"
	envoy_service_listener "github.com/cilium/proxy/go/envoy/service/listener/v3"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
)

var (
	// ErrNotImplemented is the error returned by gRPC methods that are not
	// implemented by Cilium.
	ErrNotImplemented = errors.New("not implemented")
)

// startXDSGRPCServer starts a gRPC server to serve xDS APIs using the given
// resource watcher and network listener.
// Returns a function that stops the GRPC server when called.
func startXDSGRPCServer(listener net.Listener, ldsConfig, npdsConfig, nphdsConfig, svidsConfig, bundlesConfig *xds.ResourceTypeConfiguration, resourceAccessTimeout time.Duration) context.CancelFunc {
	grpcServer := grpc.NewServer()

	xdsServer := xds.NewServer(map[string]*xds.ResourceTypeConfiguration{
		ListenerTypeURL:           ldsConfig,
		NetworkPolicyTypeURL:      npdsConfig,
		NetworkPolicyHostsTypeURL: nphdsConfig,
		SVIDsTypeURL:              svidsConfig,
		BundlesTypeURL:            bundlesConfig,
	}, resourceAccessTimeout)
	dsServer := (*xdsGRPCServer)(xdsServer)

	// TODO: https://github.com/cilium/cilium/issues/5051
	// Implement IncrementalAggregatedResources to support Incremental xDS.
	//envoy_service_discovery_v3.RegisterAggregatedDiscoveryServiceServer(grpcServer, dsServer)
	envoy_service_listener.RegisterListenerDiscoveryServiceServer(grpcServer, dsServer)
	cilium.RegisterNetworkPolicyDiscoveryServiceServer(grpcServer, dsServer)
	cilium.RegisterNetworkPolicyHostsDiscoveryServiceServer(grpcServer, dsServer)
	cilium.RegisterSVIDDiscoveryServiceServer(grpcServer, dsServer)
	cilium.RegisterBundlesDiscoveryServiceServer(grpcServer, dsServer)

	reflection.Register(grpcServer)

	go func() {
		log.Infof("Envoy: Starting xDS gRPC server listening on %s", listener.Addr())
		if err := grpcServer.Serve(listener); err != nil && !errors.Is(err, net.ErrClosed) {
			log.WithError(err).Fatal("Envoy: Failed to serve xDS gRPC API")
		}
	}()

	return grpcServer.Stop
}

// xdsGRPCServer handles gRPC streaming discovery requests for the
// resource types supported by Cilium.
type xdsGRPCServer xds.Server

// TODO: https://github.com/cilium/cilium/issues/5051
// Implement IncrementalAggregatedResources also to support Incremental xDS.
//func (s *xdsGRPCServer) StreamAggregatedResources(stream envoy_service_discovery_v3.AggregatedDiscoveryService_StreamAggregatedResourcesServer) error {
//	return (*xds.Server)(s).HandleRequestStream(stream.Context(), stream, xds.AnyTypeURL)
//}

func (s *xdsGRPCServer) DeltaListeners(stream envoy_service_listener.ListenerDiscoveryService_DeltaListenersServer) error {
	return ErrNotImplemented
}

func (s *xdsGRPCServer) StreamListeners(stream envoy_service_listener.ListenerDiscoveryService_StreamListenersServer) error {
	return (*xds.Server)(s).HandleRequestStream(stream.Context(), stream, ListenerTypeURL)
}

func (s *xdsGRPCServer) FetchListeners(ctx context.Context, req *envoy_service_discovery.DiscoveryRequest) (*envoy_service_discovery.DiscoveryResponse, error) {
	// The Fetch methods are only called via the REST API, which is not
	// implemented in Cilium. Only the Stream methods are called over gRPC.
	return nil, ErrNotImplemented
}

func (s *xdsGRPCServer) StreamNetworkPolicies(stream cilium.NetworkPolicyDiscoveryService_StreamNetworkPoliciesServer) error {
	return (*xds.Server)(s).HandleRequestStream(stream.Context(), stream, NetworkPolicyTypeURL)
}

func (s *xdsGRPCServer) FetchNetworkPolicies(ctx context.Context, req *envoy_service_discovery.DiscoveryRequest) (*envoy_service_discovery.DiscoveryResponse, error) {
	// The Fetch methods are only called via the REST API, which is not
	// implemented in Cilium. Only the Stream methods are called over gRPC.
	return nil, ErrNotImplemented
}

func (s *xdsGRPCServer) StreamNetworkPolicyHosts(stream cilium.NetworkPolicyHostsDiscoveryService_StreamNetworkPolicyHostsServer) error {
	return (*xds.Server)(s).HandleRequestStream(stream.Context(), stream, NetworkPolicyHostsTypeURL)
}

func (s *xdsGRPCServer) FetchNetworkPolicyHosts(ctx context.Context, req *envoy_service_discovery.DiscoveryRequest) (*envoy_service_discovery.DiscoveryResponse, error) {
	// The Fetch methods are only called via the REST API, which is not
	// implemented in Cilium. Only the Stream methods are called over gRPC.
	return nil, ErrNotImplemented
}

func (s *xdsGRPCServer) StreamSVIDs(stream cilium.SVIDDiscoveryService_StreamSVIDsServer) error {
	return (*xds.Server)(s).HandleRequestStream(stream.Context(), stream, SVIDsTypeURL)
}

func (s *xdsGRPCServer) FetchSVIDs(ctx context.Context, req *envoy_service_discovery.DiscoveryRequest) (*envoy_service_discovery.DiscoveryResponse, error) {
	// The Fetch methods are only called via the REST API, which is not
	// implemented in Cilium. Only the Stream methods are called over gRPC.
	return nil, ErrNotImplemented
}

func (s *xdsGRPCServer) StreamBundles(stream cilium.BundlesDiscoveryService_StreamBundlesServer) error {
	return (*xds.Server)(s).HandleRequestStream(stream.Context(), stream, BundlesTypeURL)
}

func (s *xdsGRPCServer) FetchBundles(ctx context.Context, req *envoy_service_discovery.DiscoveryRequest) (*envoy_service_discovery.DiscoveryResponse, error) {
	// The Fetch methods are only called via the REST API, which is not
	// implemented in Cilium. Only the Stream methods are called over gRPC.
	return nil, ErrNotImplemented
}
