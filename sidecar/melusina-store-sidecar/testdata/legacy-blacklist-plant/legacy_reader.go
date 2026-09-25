// Package plant is the positive control of the legacy-blacklist scan
// (TestNoStoreSourceReadsTheLegacyBlacklistAccount in blacklist_status_test.go).
// Every line between the markers below reaches the legacy ["blacklist", target]
// account, which the licence registry never creates, through one name the scan
// forbids, and the scan must report each line. It sits under testdata/, so no
// build compiles it and the module scan skips it. Removing it, or a line of it,
// fails the control by name.
package plant

func legacyReaders() {
	// plant:begin
	address, bump, err := primitives.DeriveBlacklistEntry(target, programID)
	seeds := [][]byte{primitives.SeedBlacklist, target[:]}
	present, kind, err := client.FetchBlacklistEntry(ctx, address)
	kind, err = verify.ReadBlacklistEntryType(data)
	var record verify.BlacklistEntry
	record, err = pdaread.BlacklistFromPDARead(data)
	record, err = verify.ReadBlacklist(data)
	// plant:end
}
