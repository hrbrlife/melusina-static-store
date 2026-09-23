package storerecovery

import (
	"regexp"
	"strconv"
)

// RemoteBak namespace names match ^[a-z0-9][a-z0-9-]{0,62}$ (the backup
// store's namespace pattern). A Store's state lives in generation-numbered
// namespaces, store-<storeId>-g<N>: a restore opens generation N+1 and fences
// generation N, forward-only, the same rule the spec gives tenant namespaces.
var remoteBakNamespacePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)

// StateNamespace returns the RemoteBak namespace of generation generation of
// storeID's state. It refuses a generation below one and a Store ID too long
// for the namespace to fit; the deployer must name namespaces with exactly this
// rule.
func StateNamespace(storeID string, generation uint64) (string, error) {
	if !storeIDPattern.MatchString(storeID) {
		return "", Refuse(RefusalStateNamespaceInvalid, "storeId")
	}
	if generation < 1 {
		return "", Refuse(RefusalStateNamespaceInvalid, "generation must be at least 1")
	}
	name := "store-" + storeID + "-g" + strconv.FormatUint(generation, 10)
	if !remoteBakNamespacePattern.MatchString(name) {
		return "", Refuse(RefusalStateNamespaceInvalid, "store-"+storeID+" is too long for generation "+strconv.FormatUint(generation, 10))
	}
	return name, nil
}
