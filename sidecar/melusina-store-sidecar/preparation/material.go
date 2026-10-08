// Package preparation exposes the fixed private preparation material contract.
// It provides no Store client, proposal execution or publication operation.
package preparation

import (
	"github.com/hrbrlife/melusina-store-sidecar/internal/finalizationinput"
	"github.com/hrbrlife/melusina-store-sidecar/internal/preparationenvelope"
)

type Input = finalizationinput.Input
type Ceremony = finalizationinput.CeremonyState
type Release = finalizationinput.ReleaseClaims
type EnvelopeRequest = preparationenvelope.Request
type EnvelopeResponse = preparationenvelope.Response
type EnvelopeClient = preparationenvelope.Client

const InputSchema = finalizationinput.PreparedSchema
const EnvelopeRequestSchema = preparationenvelope.RequestSchema

func DecodeInput(raw []byte, maximum int64) (Input, error) {
	return finalizationinput.Decode(raw, maximum)
}
func DecodeCeremony(raw []byte) (Ceremony, error) {
	return finalizationinput.DecodePreparedCeremony(raw)
}
func NewEnvelopeClient(socket string) (*EnvelopeClient, error) {
	if err := preparationenvelope.CheckSocket(socket); err != nil {
		return nil, err
	}
	return preparationenvelope.NewClient(socket)
}
