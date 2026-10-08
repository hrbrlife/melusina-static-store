package storelink

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strings"
)

func preparationStageReturnRoute(path string) (string, bool) {
	if !strings.HasSuffix(path, "/stage-receipt") {
		return "", false
	}
	return jobResultRoute(strings.TrimSuffix(path, "/stage-receipt"), releasePreparationJobCollection)
}

// This route can return only the original Store's private staging receipt to
// its existing job. It cannot carry proposal, transaction or approval inputs.
func (h *Handler) handlePreparationStageReturn(w http.ResponseWriter, r *http.Request, jobID string) {
	if r.URL.RawQuery != "" || r.ContentLength > maxJobRequestBytes || !isJSONContentType(r.Header.Get("Content-Type")) {
		http.Error(w, "Private stage return requires bounded JSON.", http.StatusBadRequest)
		return
	}
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxJobRequestBytes))
	var returned struct {
		Schema        string `json:"schema"`
		StoreID       string `json:"storeId"`
		RequestDigest string `json:"requestDigest"`
		OfferDigest   string `json:"offerDigest"`
		Receipt       struct {
			Schema            string `json:"schema"`
			StageID           string `json:"stageId"`
			AppID             string `json:"appId"`
			AppHash           string `json:"appHash"`
			ReleaseHash       string `json:"releaseHash"`
			ServingDomainHash string `json:"servingDomainHash"`
			StoredAt          int64  `json:"storedAt"`
			OperatorSignature string `json:"operatorSignature"`
		} `json:"receipt"`
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err != nil || d.Decode(&returned) != nil || d.Decode(&struct{}{}) != io.EOF || returned.Schema != "bazaar-control-private-stage-return-v1" || returned.StoreID != h.storeID || !isLowerHex(returned.RequestDigest, 64) || returned.RequestDigest[:24] != jobID || !isLowerHex(returned.OfferDigest, 64) || returned.Receipt.Schema != "melusina-app-stage-receipt-v1" || !isLowerHex(returned.Receipt.StageID, 64) || !validSegment(returned.Receipt.AppID) || !isLowerHex(returned.Receipt.AppHash, 64) || !isLowerHex(returned.Receipt.ReleaseHash, 64) || !isLowerHex(returned.Receipt.ServingDomainHash, 64) || returned.Receipt.StoredAt <= 0 || !safeJobText(returned.Receipt.OperatorSignature) {
		http.Error(w, "Private stage return does not bind one Store job.", http.StatusBadRequest)
		return
	}
	h.forwardJobResponse(w, r, releasePreparationJobCollection, WorkerRequest{Method: http.MethodPost, Path: "/v1/" + releasePreparationJobCollection + "/" + jobID + "/stage-receipt", Body: io.NopCloser(bytes.NewReader(raw))}, true, true)
}
