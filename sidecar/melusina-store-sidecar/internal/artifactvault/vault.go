// Package artifactvault preserves the sidecar's internal import path while
// delegating all implementation to the shared Bazaar worker-vault module.
// Keeping aliases here avoids a mixed deployment where finalization uses a
// subtly different descriptor or filesystem implementation from preparation.
package artifactvault

import shared "github.com/melusina-os/melusina-artifact-vault"

type Descriptor = shared.Descriptor
type UnixClient = shared.UnixClient
type UnixClientConfig = shared.UnixClientConfig

var DescriptorFor = shared.DescriptorFor
var NewUnixClient = shared.NewUnixClient
