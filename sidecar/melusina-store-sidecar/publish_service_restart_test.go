package main

// restartPublishServiceForTest models a new process with the same persisted
// inputs and a fresh single-writer mutex. Copying the service itself would
// copy a live mutex and would not represent a restart.
func restartPublishServiceForTest(s *publishService) *publishService {
	return &publishService{
		cfg:                         s.cfg,
		cr:                          s.cr,
		operator:                    s.operator,
		assembler:                   s.assembler,
		nonces:                      s.nonces,
		appNonces:                   s.appNonces,
		controlReceipts:             s.controlReceipts,
		controlReceiptErr:           s.controlReceiptErr,
		hostApplyIssuances:          s.hostApplyIssuances,
		hostApplyIssuanceErr:        s.hostApplyIssuanceErr,
		hostApplyPlans:              s.hostApplyPlans,
		hostApplyPlanErr:            s.hostApplyPlanErr,
		listingRegistrar:            s.listingRegistrar,
		listingRegistrationRequired: s.listingRegistrationRequired,
		catalogGenerations:          s.catalogGenerations,
		catalogExpectedUID:          s.catalogExpectedUID,
		catalogExpectedGID:          s.catalogExpectedGID,
		now:                         s.now,
		afterAppMutation:            s.afterAppMutation,
	}
}
