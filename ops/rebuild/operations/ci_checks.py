#!/usr/bin/env python3
"""Fail closed on unavailable PG/fault coverage; keep a JSON event receipt."""
import json
import os
from pathlib import Path
import subprocess
import sys
from urllib.parse import urlparse

MANDATORY = {
    'TestMigrationsPostgres', 'TestRuntimeRolePostgres',
    'TestAtomicReplayConflictAndDedupPostgres',
    'TestConcurrentClaimsAndStaleFencePostgres',
    'TestLeaseExpiresDuringDerivedWriteRollsBackPostgres',
    'TestProcessDeathBeforeCommitAndAfterCommitBeforeACKPostgres',
    'TestWorkerRecoversAfterActualPostgresProcessRestart',
    'TestSenderSIGKILLAfterReceiverAcceptanceRemainsUncertainPostgres',
    'TestWorkerSIGKILLDerivedTransactionRollsBackAndReclaimsPostgres',
    'TestQueuedDeliveryRevalidatesRevokedSourcePolicyAndEvidencePostgres',
    'TestAcceptanceStoriesABCSyntheticPostgresAndPrivateAPI',
    'TestStartupWithoutLLMPostgres',
    'TestProductFeedToPrivateAPIAndUncertainDeliveryPostgres',
    'TestDomainCopiesEditPolicyStageAndClaimsPostgres',
    'TestEvidenceValidationAndNativeDeletionBothOrdersPostgres',
    'TestStructuredFeedsPermissionQuotaTTLAndPrivateDomainAPIPostgres',
    'TestManifestHistoryDryRunAndStatePreservationPostgres',
    'TestTelegramLeaseLossClosesBeforeTakeoverAndFloodWaitPersistsPostgres',
    'TestTelegramAtomicAllowlistNativeStateAndOwnershipPostgres',
    'TestAIDurableConcurrentBudgetTimeoutBadRefsAndPrivacyPostgres',
    'TestAIAllFourteenConsumersPostgresHTTPS',
    'TestAIConfigCASSecretsCoalescenceErrorsAndRevocationPostgres',
    'TestAIUsagePresenceAndAccountingExceptionsPostgres',
    'TestAILastSegmentObservableContextCacheAndVisibleLimitPostgres',
    'TestProjectionTransitiveThreeCasesPostgres',
    'TestAttentionCASExportTTLDiscoveryQuotaAndPausePostgresHTTPS',
    'TestRetentionSharedBlobRedactsDerivedAndEvidencePostgresHTTPS',
    'TestRetentionLegacyHistoryCannotReconstructExpiredOriginalPostgresHTTPS',
    'TestWebAdaptersCaptureAuthPaginationParserReplayPostgres',
    'TestGraphNeighborLimitAndClaimDependencyPaginationPostgresHTTPS',
    'TestLivenessIndependentOfDatabaseReadinessFailsClosed',
    'TestInventoryRPCAllowlistAndBudget',
    'TestInventoryHasNoPersistenceAndErrorsDoNotPauseAccount',
    'TestInventoryCanceledSessionRemainsByteIdenticalAndNoLogin',
    'TestInventoryDialogCursorUsesPeerAndMessageID',
    'TestWebAdaptersIdentityParserPaginationAndHostileHTML',
    'TestTorSOCKSRemoteDNSRestrictedProfileFailClosed',
    'TestCore005PIRRevisionPauseOwnSourceAndDiscoveryRevokePostgresHTTPS',
    'TestCore005RSSPauseDuringFetchDoesNotAdvanceCheckpointPostgres',
    'TestCore005PIRPauseFencesTelegramPayloadAndBootstrapPostgresHTTPS',
    'TestCore005PIREditsReprocessCurrentTermsWithoutFalseMaterialChangePostgresHTTPS',
    'TestCore005WorkerReadThenPurgeCannotRegrowDerivativesPostgresHTTPS',
    'TestCore005OwnPauseParksAndResumesDurablyWithoutRevivingInvalidJobsPostgresHTTPS',
    'TestCore005OwnResumeWinsFinishAdmissionWithoutLostWakePostgres',
    'TestCore005DeliveryAdmissionOrdersRevocationAndUncertainPostgres',
    'TestCore005RetentionMultiCitationReasonCannotRecomposePostgresHTTPS',
    'TestIOAIStableGuardOrdersConfigAndPIRRevocationPostgresHTTPS',
    'TestIOEnrichmentGuardAndRevokedCachePublicationPostgres',
    'TestIODiscoveryTrialGuardAndRevokedPublicationPostgres',
    'TestNativeAdmissionRevocationResponseAndCancellationPostgres',
    'TestNativeChannelRevokedBetweenPagesAndHistoryIdentityPostgres',
    'TestNativeBudgetDowntimeExpiryAndAtomicFailurePostgres',
    'TestAuthenticationModeCannotInvokeCaptureOrPersistUpdates',
    'TestNativeBudgetAtomicCapsReplayAndMetadataPostgres',
    'TestNativeBudgetAPIAllPhasesRestartAndUncertainPostgres',
    'TestNativeBudgetMiddlewareStartupAndNestedAdmissionsPostgres',
    'TestNativeBudgetConcurrentFinalAdmissionAndDBDownPostgres',
    'TestNativeBudgetStrictPolicyAndStableSidecar',
    'TestNativeBudgetSIGKILLReservationAndCommitBoundariesPostgres',
    'TestNativeBudgetCompiledCLIValidateStatusAndRequiredPolicyPostgres',
    'TestNativeBudgetRejectsStoredOldConsentAndMissingBindingPostgres',
    'TestNativeBudgetGlobalPersistedAndPhaseCapsPostgres',
    'TestNativeBudgetRuntimeRoleAdmissionAndCommitWithoutDDLPostgres',
    'TestNativeStartupRejectsBeforeRealRunResolverPostgres',
    'TestNativeStartupRealRunSelfAndDurableControlPostgres',
    'TestNativeStartupRealRunCancelClosesBeforeGuardReleasePostgres',
    'TestNativeStartupRealRunRejectsReconnectBeforeBaseResolverPostgres',
    'TestNativeStartupResolverRejectsAdditionalEstablishments',
    'TestNativeResolveFailurePersistsPauseAndAdmissionPostgres',
    'TestProductionRuntimeRoleAdmissionAndAtomicCommitPostgres',
    'TestProductionNoHistoryBeforePayloadAndTooLongPostgres',
    'TestProductionRejectedBatchDurableWaitRestartAndRolloverPostgres',
    'TestProductionRenewalRestartAndUncertainNoResetPostgres',
    'TestProductionRenewalCASAndExhaustedSupervisorNoClientPostgres',
    'TestProductionConcurrentFinalAdmissionAndRolloverPostgres',
    'TestProductionExpiryRevocationWrongGenerationAndDBDownPostgres',
    'TestProductionUncertaintyDurableAcrossParentRestartAndManualResumePostgres',
    'TestProductionPurePlannedCloseAllowedMixedFailureBlockedPostgres',
    'TestProductionFencePersistenceFailureNeverRecordsClosurePostgres',
    'TestProductionExpiredConsentCannotManualResumePostgres',
    'TestProductionPersistedFloodWaitAllowsOnlyKnownFailurePostgres',
    'TestGenerationTransitionPreparationFencesAndRepairPostgres',
    'TestGenerationTransitionCASRollbackAndWaitPostgres',
    'TestGenerationPilotAuthenticationPreflightNoMutationPostgres',
    'TestGenerationSuccessorQuotaRolloverAndRepeatedRotationPostgres',
    'TestTelegramGenerationTransitionOnboardingPostgresHTTPS',
    'TestTelegramEmptyCandidatesPausedActivateReimportPostgresHTTPS',
    'TestTelegramMissingBaselineCannotActivatePostgresHTTPS',
    'TestTelegramOnboardingBrowserPostgresHTTPS',
    'TestMechanicalWorkerDoesNotExecuteOrPlanConfiguredAIPostgres',
    'TestRealAIResumePostgresHTTPS',
    'TestIOAIProjectionBindingDeadlinePostgresHTTPS',
    'TestRealAIPublicationDispositionPostgresHTTPS',
    'TestResultValidationClosedCategories',
    'TestResponsesContextOnlyContractThroughWireAndValidator',
    'TestImmutablePromptRegistry',
    'TestWirePromptVersionAndUnknownBeforePOST',
    'TestPromptVersionsSeparateCacheIdentity',
    'TestDefaultConfigUsesPromptV2AndRejectsUnknown',
    'TestCompleteReceiptRequiresExactV2FunctionSet',
    'TestPromptTransitionRejectsIncompatiblePendingPostgres',
}
# Only child helpers may deliberately skip when not launched by their parent.
CHILDREN = {'TestCaptureCrashChild', 'TestDomainProcessChild', 'TestNativeBudgetCrashProcessHelper'}

def main():
    parsed = urlparse(os.environ.get('NOCTIS_V2_TEST_DATABASE_URL', ''))
    if parsed.hostname != '127.0.0.1' or 'v2_test' not in parsed.path:
        raise RuntimeError('Explicit loopback synthetic PostgreSQL test database required')
    image = os.environ.get('NOCTIS_V2_FAULT_DOCKER_IMAGE', '')
    if not image:
        raise RuntimeError('Explicit local PostgreSQL16 fault image required')
    subprocess.run(['docker', 'image', 'inspect', image], check=True, stdout=subprocess.DEVNULL)
    receipt = Path(os.environ.get('NOCTIS_V2_CHECK_RECEIPT', '/tmp/noctis-v2-go-tests.jsonl'))
    passed, skipped = set(), []
    environment = dict(os.environ, NOCTIS_ONBOARDING_BROWSER='1',
                       NOCTIS_AI_RESUME_TEST_DATABASE_URL=os.environ['NOCTIS_V2_TEST_DATABASE_URL'])
    process = subprocess.Popen(['go', 'test', '-json', '-race', '-count=1', './...'], stdout=subprocess.PIPE, text=True, env=environment)
    with receipt.open('w') as output:
        for line in process.stdout:
            output.write(line)
            try:
                event = json.loads(line)
            except ValueError:
                continue
            action, test = event.get('Action'), event.get('Test', '')
            if action == 'pass' and test:
                passed.add(test)
            if action == 'skip' and test and test not in CHILDREN:
                skipped.append(event.get('Package', '') + '/' + test)
            if action == 'fail':
                print(event, file=sys.stderr)
    status = process.wait()
    missing = MANDATORY - passed
    if status or missing or skipped:
        raise RuntimeError(f'Go checks failed: exit={status}, mandatory_missing={sorted(missing)}, unexpected_skips={skipped}; receipt={receipt}')
    print(f'Go race suite PASS; mandatory={len(MANDATORY)}; unexpected_skips=0; receipt={receipt}')

if __name__ == '__main__':
    main()
