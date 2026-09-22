//go:build estatebootstrap

package runtimecontract

// SchemaURL is a stable protocol identifier, not an endpoint selected by an
// estate. A fresh bootstrap build must not bake a retiring Store hostname into
// every future runtime-contract declaration.
const SchemaURL = "urn:melusina:runtime-contract:v1"
