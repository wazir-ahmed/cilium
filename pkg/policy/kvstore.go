package policy

import (
	"context"
	"encoding/json"
	"path"
	"strings"
	"time"

	k8sUtils "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/utils"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/policy/api"
	"github.com/sirupsen/logrus"
)

type policyWatcher struct {
	backend       kvstore.BackendOperations
	policyManager PolicyManager
}

var (
	// CCNPPath is the path to where CCNPs are stored in the key-value store.
	CCNPPath = path.Join(kvstore.BaseKeyPrefix, "state", "policies", "v1", "ccnp")
)

func newPolicyWatcher(backend kvstore.BackendOperations, policyManger PolicyManager) *policyWatcher {
	return &policyWatcher{
		backend,
		policyManger,
	}
}

func InitPolicyWatcher(pm PolicyManager) {
	watcher := newPolicyWatcher(kvstore.Client(), pm)
	go func() {
		log.Info("Starting policy watcher")
		watcher.CCNPWatch(context.TODO())
	}()
}

func (w *policyWatcher) CCNPWatch(ctx context.Context) {
	var scopedLog *logrus.Entry
	var policyName string
	var policyLabels labels.LabelArray

restart:
	watcher := kvstore.Client().ListAndWatch(ctx, "CCNPWatcher", CCNPPath, 512)

	for {
		select {
		case event, ok := <-watcher.Events:
			if !ok {
				log.Debugf("%s closed, restarting watch", watcher.String())
				time.Sleep(500 * time.Millisecond)
				goto restart
			}

			scopedLog = log.WithFields(logrus.Fields{"kvstore-event": event.Typ.String(), "key": event.Key})
			scopedLog.Debug("Received event")

			if event.Typ != kvstore.EventTypeListDone {
				policyName = strings.TrimPrefix(event.Key, (CCNPPath + "/"))
				policyLabels = labels.LabelArray{
					labels.NewLabel("policy.name", policyName, labels.LabelSourceCiliumGenerated),
					labels.NewLabel("policy.derived-from", k8sUtils.ResourceTypeCiliumClusterwideNetworkPolicy, labels.LabelSourceCiliumGenerated),
				}
			}

			switch event.Typ {
			case kvstore.EventTypeCreate, kvstore.EventTypeModify:
				var ccnp api.Rule
				err := json.Unmarshal(event.Value, &ccnp)
				if err != nil {
					scopedLog.WithError(err).Error("Error unmarshaling data from kvstore")
					continue
				}

				if err := ccnp.Sanitize(); err != nil {
					metrics.PolicyImportErrorsTotal.Inc()
					scopedLog.WithError(err).Error("Failed to add CCNP from kvstore")
					continue
				}

				ccnp.Labels = append(ccnp.Labels, policyLabels...)

				_, err = w.policyManager.PolicyAdd(api.Rules{&ccnp}, &AddOptions{
					ReplaceWithLabels: policyLabels,
					Source:            metrics.LabelEventSourceK8s,
				})

				if err != nil {
					metrics.PolicyImportErrorsTotal.Inc()
					scopedLog.WithError(err).Error("Failed to add CCNP from kvstore")
				} else {
					scopedLog.Info("Imported CCNP from kvstore")
				}

			case kvstore.EventTypeDelete:
				_, err := w.policyManager.PolicyDelete(policyLabels)
				if err != nil {
					scopedLog.WithError(err).Error("Failed to delete CCNP")
				} else {
					scopedLog.Info("Deleted CCNP")
				}
			}
		case <-ctx.Done():
			// Stop this policy watcher, we have been signaled to shut down
			// via context.
			watcher.Stop()
			return
		}
	}
}
