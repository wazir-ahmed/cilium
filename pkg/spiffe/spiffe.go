// Copyright 2021 Authors of Cilium
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

package spiffe

import (
	"context"
	"fmt"
	"math/rand"
	"strconv"
	"sync"
	"time"

	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"

	delegationv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/agent/delegation/v1"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"

	"google.golang.org/grpc"
)

const (
	spiffeSubsys = "spiffe"
	timeDelay    = 10 * time.Second

	// TODO(Mauricio): This should be configurable.
	localTrustDomain = "spiffe://example.org"
)

var (
	log = logging.DefaultLogger.WithField(logfields.LogSubsys, spiffeSubsys)
)

type SpiffeSVID struct {
	SpiffeID  string
	CertChain []byte
	Key       []byte
	ExpiresAt int64
}

type UpdateFunc func([]*SpiffeSVID)

type BundleUpdater interface {
	UpdateBundle(trustDomainName string, bundle []byte)
}

const (
	ADD int = 1
	DEL     = 2
)

type request struct {
	typ        int
	pod        *slim_corev1.Pod
	updateFunc UpdateFunc
}

type Watcher struct {
	stream delegationv1.Delegation_FetchX509SVIDsClient

	updateFuncs map[uint64]UpdateFunc

	ids map[*slim_corev1.Pod]uint64

	requests map[*slim_corev1.Pod]request

	bundleUpdater BundleUpdater

	mutex *lock.Mutex
	cv    *sync.Cond

	processRequestsDone bool
}

func NewWatcher(bundleUpdater BundleUpdater) *Watcher {
	w := &Watcher{
		updateFuncs:   make(map[uint64]UpdateFunc),
		ids:           make(map[*slim_corev1.Pod]uint64),
		requests:      make(map[*slim_corev1.Pod]request),
		bundleUpdater: bundleUpdater,
		mutex:         &lock.Mutex{},
	}

	w.cv = sync.NewCond(w.mutex)
	return w
}

func (s *Watcher) Start() {
	go s.run()
	go s.runBundlesWatcher()
}

func (s *Watcher) startProcessRequests() {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	// rewatch for all pods
	for pod, id := range s.ids {
		protoReq := &delegationv1.FetchX509SVIDsRequest{
			Operation: delegationv1.FetchX509SVIDsRequest_ADD,
			Id:        id,
			Selectors: getPodSelectors(pod),
		}

		err := s.stream.Send(protoReq)
		if err != nil {
			log.WithError(err).Debugf("spiffe: failed to add pod to watch set")
			// what to do here?
			continue
		}
	}

	// start processing ADD/DEL requests again
	s.processRequestsDone = false
	go s.processRequests()
}

func (s *Watcher) processRequests() {
	for {
		// TODO: this lock is locking way too much. Try to avoid helding it when
		// performing network operations
		s.mutex.Lock()
		for len(s.requests) == 0 && !s.processRequestsDone {
			s.cv.Wait()
		}

		if s.processRequestsDone {
			s.mutex.Unlock()
			return
		}

		// get first element of map
		var req request
		for _, v := range s.requests {
			req = v
			break
		}

		switch req.typ {
		case ADD:
			log.Debug("spiffe: processing ADD operation")
			id := rand.Uint64()

			protoReq := &delegationv1.FetchX509SVIDsRequest{
				Operation: delegationv1.FetchX509SVIDsRequest_ADD,
				Id:        id,
				Selectors: getPodSelectors(req.pod),
			}

			err := s.stream.Send(protoReq)
			if err != nil {
				log.WithError(err).Debugf("spiffe: failed to add pod to watch set")
				s.mutex.Unlock()
				return
			}

			s.ids[req.pod] = id
			s.updateFuncs[id] = req.updateFunc

		case DEL:
			id, ok := s.ids[req.pod]
			if !ok {
				log.Debugf("spiffe: spiffe ID for pod %s not found", req.pod.Name)
				continue
			}

			protoReq := &delegationv1.FetchX509SVIDsRequest{
				Operation: delegationv1.FetchX509SVIDsRequest_DEL,
				Id:        id,
			}

			err := s.stream.Send(protoReq)
			if err != nil {
				log.WithError(err).Debugf("spiffe: failed to remove pod from watch set")
				s.mutex.Unlock()
				return
			}

			delete(s.ids, req.pod)
			delete(s.updateFuncs, id)
		}

		// request was processed, remove it!
		delete(s.requests, req.pod)
		s.mutex.Unlock()
	}
}

func (s *Watcher) run() {
	firstTime := true

	for {
		if firstTime == false {
			// stop processing ADD/DEL requests
			s.processRequestsDone = true
			s.cv.Signal()

			// TODO: use backoff?
			time.Sleep(timeDelay)
		} else {
			firstTime = false
		}

		log.Debugf("spiffe: trying to connect")

		unixPath := "unix://" + option.Config.SpirePrivilegedAPISocketPath
		conn, err := grpc.Dial(unixPath, grpc.WithInsecure())
		if err != nil {
			log.WithError(err).Warning("spiffe: failed to connect to delegation SPIRE socket")
			continue
		}

		client := delegationv1.NewDelegationClient(conn)

		ctx := context.Background()
		s.stream, err = client.FetchX509SVIDs(ctx)
		if err != nil {
			log.WithError(err).Warning("spiffe: failed to create delegation SPIRE api client")
			continue
		}

		// get greeting message from stream
		if _, err := s.stream.Recv(); err != nil {
			log.WithError(err).Warning("spiffe: failed to read delegation SPIRE api (greeting message)")
			continue
		}

		// Everything is working fine at this point
		log.Debug("spiffe: everything is working fine")
		s.startProcessRequests()

		for {
			resp, err := s.stream.Recv()
			if err != nil {
				// TODO: specific error message if cilium agent registration entry is missing.
				log.WithError(err).Warning("spiffe: failed to read delegation SPIRE api")
				break
			}

			s.mutex.Lock()
			updateFunc, ok := s.updateFuncs[resp.Id]
			s.mutex.Unlock()
			if !ok {
				continue
			}

			spiffeSvids := make([]*SpiffeSVID, len(resp.X509Svids))
			for idx, svid := range resp.X509Svids {
				var certChain []byte
				for _, cert := range svid.X509Svid.CertChain {
					certChain = append(certChain, cert...)
				}

				spiffeSvids[idx] = &SpiffeSVID{
					SpiffeID:  spiffeIDToString(svid.X509Svid.Id),
					CertChain: certChain,
					Key:       svid.X509SvidKey,
					ExpiresAt: svid.X509Svid.ExpiresAt,
				}

			}

			updateFunc(spiffeSvids)
		}
	}
}

// Watch adds the pod to the watched list. updateFunc will be called when there
// is an update for such a pod.
func (s *Watcher) Watch(pod *slim_corev1.Pod, updateFunc UpdateFunc) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	// If we already have an DEL request, remove it
	if req, ok := s.requests[pod]; ok && req.typ == DEL {
		delete(s.requests, pod)
		return nil
	}

	s.requests[pod] = request{
		typ:        ADD,
		pod:        pod,
		updateFunc: updateFunc,
	}

	s.cv.Signal()

	return nil
}

// Unwatch removes a pod from the watched list.
func (s *Watcher) Unwatch(pod *slim_corev1.Pod) error {
	if pod == nil {
		return nil
	}

	if s == nil || s.mutex == nil {
		// "segmentation violation" occours at s.mutex.Lock()
		// - monitors others crashs in s.mutex.Lock()
		log.Errorf("spiffe(Unwatch): problem with object Watcher or mutex")
		return nil
	}

	s.mutex.Lock()
	defer s.mutex.Unlock()

	// If we already have an ADD request, remove it
	if req, ok := s.requests[pod]; ok && req.typ == ADD {
		delete(s.requests, pod)
		return nil
	}

	s.requests[pod] = request{
		typ: DEL,
		pod: pod,
	}

	s.cv.Signal()

	return nil
}

func makeSelector(format string, args ...interface{}) *types.Selector {
	return &types.Selector{
		Type:  "k8s",
		Value: fmt.Sprintf(format, args...),
	}
}

func getPodSelectors(pod *slim_corev1.Pod) []*types.Selector {
	// missing ones:
	// - image with sha256
	// - owner references
	selectors := []*types.Selector{
		makeSelector("sa:%s", pod.Spec.ServiceAccountName),
		makeSelector("ns:%s", pod.Namespace),
		makeSelector("node-name:%s", pod.Spec.NodeName),
		makeSelector("pod-uid:%s", pod.UID),
		makeSelector("pod-name:%s", pod.Name),
		makeSelector("pod-image-count:%s", strconv.Itoa(len(pod.Spec.Containers))),
		makeSelector("pod-init-image-count:%s", strconv.Itoa(len(pod.Spec.InitContainers))),
	}

	for _, container := range pod.Spec.Containers {
		selectors = append(selectors, makeSelector("pod-image:%s", container.Image))
	}
	for _, container := range pod.Spec.InitContainers {
		selectors = append(selectors, makeSelector("pod-init-image:%s", container.Image))
	}

	for k, v := range pod.Labels {
		selectors = append(selectors, makeSelector("pod-label:%s:%s", k, v))
	}
	//	for _, ownerReference := range pod.OwnerReferences {
	//		selectors = append(selectors, makeSelector("pod-owner:%s:%s", ownerReference.Kind, ownerReference.Name))
	//		selectors = append(selectors, makeSelector("pod-owner-uid:%s:%s", ownerReference.Kind, ownerReference.UID))
	//	}

	return selectors
}

func spiffeIDToString(id *types.SPIFFEID) string {
	return "spiffe://" + id.TrustDomain + id.Path
}

func (s *Watcher) runBundlesWatcher() {
	firstTime := true

	for {
		if firstTime == false {
			// TODO: use backoff?
			time.Sleep(timeDelay)
		} else {
			firstTime = false
		}

		log.Debugf("spiffe(bundles): trying to connect")

		unixPath := "unix://" + option.Config.SpirePrivilegedAPISocketPath
		conn, err := grpc.Dial(unixPath, grpc.WithInsecure())
		if err != nil {
			log.WithError(err).Warning("spiffe: failed to connect to delegation SPIRE socket")
			continue
		}

		client := delegationv1.NewDelegationClient(conn)

		ctx := context.Background()
		stream, err := client.FetchX509Bundles(ctx, &delegationv1.FetchX509BundlesRequest{})
		if err != nil {
			log.WithError(err).Warning("spiffe(bundles): failed to create delegation SPIRE api client")
			continue
		}

		// Everything is working fine at this point
		log.Debug("spiffe(bundles): everything is working fine")

		for {
			resp, err := stream.Recv()
			if err != nil {
				// TODO: specific error message if cilium agent registration entry is missing.
				log.WithError(err).Warning("spiffe(bundles): failed to read delegation SPIRE api")
				break
			}
			if resp.TrustDomainName == localTrustDomain {
				resp.TrustDomainName = "LOCAL"
			}
			s.bundleUpdater.UpdateBundle(resp.TrustDomainName, resp.Bundle)
		}
	}
}
