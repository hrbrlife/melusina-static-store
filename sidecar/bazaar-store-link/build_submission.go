package storelink

import (
	"context"
	"encoding/json"
	"errors"
)

const buildSubmissionSchema = "bazaar-control-trusted-build-submission-v1"
const buildSubmissionPath = "/v1/build-submissions"
const maxBuildSubmissionBytes = maxSelectedReleaseResponseBytes + (maxJobRequestBytes*4)/3 + (64 << 10)

// This envelope exists only on the connector's pinned worker hop. The browser
// cannot submit it: its route accepts the unchanged, narrow source intent.
// JSON artifact byte fields remain base64 within the original snapshot; the
// outer locator object needs no second base64 expansion or new signature.
type buildSubmission struct {
	Schema          string          `json:"schema"`
	SourceIntent    []byte          `json:"sourceIntentBytes"`
	SelectedRelease json.RawMessage `json:"selectedRelease"`
}

func (h *Handler) buildSubmission(ctx context.Context, original []byte) ([]byte, error) {
	var request buildStartRequest
	if err := json.Unmarshal(original, &request); err != nil || request.StoreID != h.storeID {
		return nil, errors.New("source intent belongs to another Store")
	}
	selected, err := h.readSelectedRelease(ctx, request.AppID)
	if err != nil {
		return nil, err
	}
	raw, err := json.Marshal(buildSubmission{Schema: buildSubmissionSchema, SourceIntent: original, SelectedRelease: selected})
	if err != nil || int64(len(raw)) > maxBuildSubmissionBytes {
		return nil, errors.New("internal build evidence exceeds its bound")
	}
	return raw, nil
}
