package policy

import (
	"path"

	"github.com/cilium/cilium/pkg/kvstore"
)

var (
	// CCNPPath is the path to where CCNPs are stored in the key-value store.
	CCNPPath = path.Join(kvstore.BaseKeyPrefix, "state", "policies", "v1", "ccnp")
)
