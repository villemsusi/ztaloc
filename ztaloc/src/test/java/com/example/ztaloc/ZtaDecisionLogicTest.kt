package com.example.ztaloc

import com.example.ztaloc.api.AccessDecision
import com.example.ztaloc.behavior.BehaviorMonitor
import com.example.ztaloc.context.ContextSignals
import com.example.ztaloc.core.ZtaConfig
import com.example.ztaloc.data.SessionRecord
import com.example.ztaloc.device.DevicePosture
import com.example.ztaloc.device.RootIntegrityChecks
import com.example.ztaloc.location.LocationTransformer
import com.example.ztaloc.location.PreciseLocation
import com.example.ztaloc.policy.PolicyEvaluator
import com.example.ztaloc.policy.TrustInputs
import com.example.ztaloc.policy.TrustScoreEngine
import org.junit.Assert.assertThrows
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class ZtaDecisionLogicTest {
    @Test
    fun behaviorMonitorFlagsBurstRequestsAndRepeatedFailures() {
        val now = 1_700_000_000_000L
        val sessions = listOf(
            SessionRecord("1", "requester", "target", now - 10_000L, 0, AccessDecision.DENY.name),
            SessionRecord("2", "requester", "target", now - 20_000L, 0, AccessDecision.DENY.name),
            SessionRecord("3", "requester", "target", now - 30_000L, 0, AccessDecision.REQUIRE_STEP_UP.name),
            SessionRecord("4", "requester", "target", now - 40_000L, 90, AccessDecision.ALLOW_PRECISE.name),
            SessionRecord("5", "requester", "target", now - 50_000L, 80, AccessDecision.ALLOW_APPROXIMATE.name)
        )

        val signals = BehaviorMonitor().collect(sessions, now)

        assertFalse(signals.normalRequestRate)
        assertTrue(signals.repeatedFailures)
        assertTrue(signals.notes.contains("Burst request pattern detected"))
        assertTrue(signals.notes.contains("Repeated prior failures"))
    }

    @Test
    fun behaviorMonitorFlagsImpossibleMovementFromLocationHistory() {
        val now = 1_700_000_000_000L
        val sessions = listOf(
            SessionRecord(
                "1",
                "requester",
                "target",
                now - 60_000L,
                90,
                AccessDecision.ALLOW_PRECISE.name,
                locationLatitude = 59.4370,
                locationLongitude = 24.7536,
                locationTimestampEpochMs = now - 60_000L
            ),
            SessionRecord(
                "2",
                "requester",
                "target",
                now,
                90,
                AccessDecision.ALLOW_PRECISE.name,
                locationLatitude = 48.8566,
                locationLongitude = 2.3522,
                locationTimestampEpochMs = now
            )
        )

        val signals = BehaviorMonitor().collect(sessions, now)

        assertTrue(signals.impossibleMovementSuspected)
        assertTrue(signals.notes.contains("Implausible movement pattern detected"))
    }

    @Test
    fun rootIntegrityChecksDetectTestKeysAndSuspiciousBuilds() {
        assertTrue(RootIntegrityChecks.hasTestKeys("release-keys,test-keys"))
        assertFalse(RootIntegrityChecks.hasTestKeys("release-keys"))
        assertTrue(RootIntegrityChecks.hasSuspiciousBuildTags(buildType = "userdebug", buildFingerprint = "brand/device/userdebug"))
        assertTrue(RootIntegrityChecks.hasSuspiciousBuildTags(buildType = "user", buildFingerprint = "generic/sdk/generic"))
        assertFalse(RootIntegrityChecks.hasSuspiciousBuildTags(buildType = "user", buildFingerprint = "brand/device/release"))
    }

    @Test
    fun policyRequiresStepUpWhenLocalAuthenticationIsMissing() {
        val score = TrustScoreEngine().calculate(
            TrustInputs(
                identityAuthenticated = false,
                multiFactorSatisfied = false,
                devicePosture = trustedDevicePosture(),
                contextSignals = trustedContextSignals(),
                behaviorSignals = BehaviorMonitor().collect()
            )
        )

        val policy = PolicyEvaluator().evaluate(score)

        assertEquals(AccessDecision.REQUIRE_STEP_UP, policy.decision)
    }

    @Test
    fun policyAllowsPreciseLocationForFullyTrustedInputs() {
        val score = TrustScoreEngine().calculate(
            TrustInputs(
                identityAuthenticated = true,
                multiFactorSatisfied = true,
                devicePosture = trustedDevicePosture(),
                contextSignals = trustedContextSignals(),
                behaviorSignals = BehaviorMonitor().collect()
            )
        )

        val policy = PolicyEvaluator().evaluate(score)

        assertEquals(100, score.total)
        assertEquals(AccessDecision.ALLOW_PRECISE, policy.decision)
    }

    @Test
    fun policyThresholdsAreConfigurable() {
        val policy = PolicyEvaluator(
            preciseThreshold = 100,
            approximateThreshold = 90,
            semanticThreshold = 80,
            minimumCategoryScore = 0
        ).evaluate(85)

        assertEquals(AccessDecision.ALLOW_SEMANTIC, policy.decision)
    }

    @Test
    fun ztaConfigRejectsInvalidThresholdOrdering() {
        assertThrows(IllegalArgumentException::class.java) {
            ZtaConfig(
                preciseThreshold = 60,
                approximateThreshold = 70,
                semanticThreshold = 50
            )
        }
    }

    @Test
    fun approximateLocationRadiusUsesConfiguredOffset() {
        val payload = LocationTransformer(approximateMaxOffsetKm = 5.0).transform(
            location = PreciseLocation(59.4370, 24.7536, 1_700_000_000_000L),
            exposure = com.example.ztaloc.api.LocationExposure.APPROXIMATE
        )

        assertEquals(7_071.067811865476, payload.radiusMeters ?: 0.0, 0.0001)
    }

    private fun trustedDevicePosture(): DevicePosture {
        return DevicePosture(
            isRegistered = true,
            passesIntegrity = true,
            osVersionRecentEnough = true,
            secureLockEnabled = true,
            hardwareBackedKeysAvailable = true,
            rootOrJailbreakSuspected = false,
            rationale = emptyList()
        )
    }

    private fun trustedContextSignals(): ContextSignals {
        return ContextSignals(
            trustedNetwork = true,
            requestHour = 12,
            withinExpectedHours = true,
            requestFresh = true,
            notes = emptyList()
        )
    }
}
