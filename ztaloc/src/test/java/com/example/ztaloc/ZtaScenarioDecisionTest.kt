package com.example.ztaloc

import com.example.ztaloc.api.AccessDecision
import com.example.ztaloc.behavior.BehaviorMonitor
import com.example.ztaloc.behavior.BehaviorSignals
import com.example.ztaloc.context.ContextSignals
import com.example.ztaloc.core.ZtaConfig
import com.example.ztaloc.data.SessionRecord
import com.example.ztaloc.device.DevicePosture
import com.example.ztaloc.policy.PolicyEvaluator
import com.example.ztaloc.policy.TrustInputs
import com.example.ztaloc.policy.TrustRecencySignals
import com.example.ztaloc.policy.TrustScoreEngine
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class ZtaScenarioDecisionTest {
    private val now = 1_700_000_000_000L

    @Test
    fun baselineAllowsPreciseLocation() {
        val result = evaluate()
        printScenario("Baseline", result)

        assertEquals(100, result.score)
        assertEquals(AccessDecision.ALLOW_PRECISE, result.decision)
    }

    @Test
    fun rootedDeviceIsDenied() {
        val result = evaluate(devicePosture = trustedDevicePosture().copy(rootOrJailbreakSuspected = true))
        printScenario("Rooted device", result)

        assertEquals(AccessDecision.DENY, result.decision)
    }

    @Test
    fun unknownRequesterIsDeniedAsUnregisteredDevice() {
        val result = evaluate(devicePosture = trustedDevicePosture().copy(isRegistered = false))
        printScenario("Unknown requester", result)

        assertEquals(AccessDecision.DENY, result.decision)
    }

    @Test
    fun suspiciousRequestsAreDenied() {
        val result = evaluate(behaviorSignals = suspiciousRequestSignals())
        printScenario("Suspicious requests", result)

        assertEquals(AccessDecision.DENY, result.decision)
    }

    @Test
    fun checksumMismatchIsDenied() {
        val result = evaluate(devicePosture = trustedDevicePosture().copy(applicationChecksumMatches = false))
        printScenario("Checksum mismatch", result)

        assertEquals(AccessDecision.DENY, result.decision)
    }

    @Test
    fun devicePreviouslyRegisteredButLaterRemovedIsDenied() {
        val result = evaluate(devicePosture = trustedDevicePosture().copy(isRegistered = false))
        printScenario("Device previously registered but removed", result)

        assertEquals(AccessDecision.DENY, result.decision)
    }

    @Test
    fun replayAttackIsDeniedByRequestFreshness() {
        val result = evaluate(contextSignals = trustedContextSignals().copy(requestFresh = false))
        printScenario("Replay attack", result)

        assertEquals(AccessDecision.DENY, result.decision)
    }

    @Test
    fun weakDeviceSecurityIsDenied() {
        val result = evaluate(
            devicePosture = trustedDevicePosture().copy(
                secureLockEnabled = false,
                hardwareBackedKeysAvailable = false,
                permissionPolicyMatches = false,
                missingRuntimePermissions = listOf("android.permission.ACCESS_FINE_LOCATION")
            )
        )
        printScenario("Weak device security", result)

        assertEquals(AccessDecision.DENY, result.decision)
    }

    @Test
    fun lateEveningRequestKeepsAccessButLowersTrustScore() {
        val result = evaluate(contextSignals = trustedContextSignals().copy(requestHour = 22, withinExpectedHours = false))
        printScenario("Late evening request", result)

        assertEquals(AccessDecision.ALLOW_PRECISE, result.decision)
        assertTrue(result.score < 100)
    }

    @Test
    fun nighttimeAndPublicWifiAllowsApproximateLocation() {
        val result = evaluate(
            contextSignals = trustedContextSignals().copy(
                trustedNetwork = false,
                requestHour = 2,
                withinExpectedHours = false
            )
        )
        printScenario("Nighttime and public Wi-Fi", result)

        assertEquals(AccessDecision.ALLOW_APPROXIMATE, result.decision)
        assertTrue(result.score in 80..89)
    }

    @Test
    fun semanticAccessForModerateDeviceAndContextRisk() {
        val result = evaluate(
            devicePosture = trustedDevicePosture().copy(
                osVersionRecentEnough = false,
                permissionPolicyMatches = false,
                missingRuntimePermissions = listOf("android.permission.ACCESS_FINE_LOCATION")
            ),
            contextSignals = trustedContextSignals().copy(
                trustedNetwork = false,
                requestHour = 22,
                withinExpectedHours = false
            )
        )
        printScenario("Semantic moderate device and context risk", result)

        assertEquals(AccessDecision.ALLOW_SEMANTIC, result.decision)
        assertTrue(result.score in 70..79)
    }

    @Test
    fun semanticAccessForBehaviorCountryAndOsRisk() {
        val result = evaluate(
            devicePosture = trustedDevicePosture().copy(osVersionRecentEnough = false),
            contextSignals = trustedContextSignals().copy(
                requestHour = 22,
                withinExpectedHours = false,
                countryAllowed = false,
                countryIsoCode = "LV"
            ),
            behaviorSignals = trustedBehaviorSignals().copy(normalRequestRate = false),
            trustRecencySignals = trustedRecencySignals()
        )
        printScenario("Semantic behavior country and OS risk", result)

        assertEquals(AccessDecision.ALLOW_SEMANTIC, result.decision)
        assertTrue(result.score in 70..79)
    }

    @Test
    fun impossibleTravelIsDenied() {
        val result = evaluate(behaviorSignals = trustedBehaviorSignals().copy(impossibleMovementSuspected = true))
        printScenario("Impossible travel", result)

        assertEquals(AccessDecision.DENY, result.decision)
    }

    @Test
    fun requestFromNearbyButUnusualCountryKeepsAccessButLowersTrustScore() {
        val result = evaluate(
            contextSignals = trustedContextSignals().copy(
                countryAllowed = false,
                countryIsoCode = "LV"
            )
        )
        printScenario("Request from nearby but unusual country", result)

        assertEquals(AccessDecision.ALLOW_PRECISE, result.decision)
        assertTrue(result.score < 100)
    }

    @Test
    fun manyConditionsNotMetIsDeniedWithLowScore() {
        val result = evaluate(
            devicePosture = trustedDevicePosture().copy(
                isRegistered = false,
                passesIntegrity = false,
                osVersionRecentEnough = false,
                secureLockEnabled = false,
                hardwareBackedKeysAvailable = false,
                applicationChecksumMatches = false,
                permissionPolicyMatches = false,
                missingRequiredPermissions = listOf("android.permission.USE_BIOMETRIC"),
                missingRuntimePermissions = listOf("android.permission.ACCESS_FINE_LOCATION"),
                extraDeclaredPermissions = listOf("android.permission.CAMERA"),
                rootOrJailbreakSuspected = true
            ),
            contextSignals = trustedContextSignals().copy(
                trustedNetwork = false,
                requestHour = 2,
                withinExpectedHours = false,
                requestFresh = false,
                countryAllowed = false,
                countryIsoCode = "LV"
            ),
            behaviorSignals = BehaviorSignals(
                normalRequestRate = false,
                repeatedFailures = true,
                impossibleMovementSuspected = true,
                notes = listOf("Burst request pattern detected", "Repeated prior failures", "Implausible movement pattern detected")
            ),
            trustRecencySignals = TrustRecencySignals(
                lastTrustedRequestEpochMs = now - 310L * 24L * 60L * 60L * 1000L,
                monthsSinceLastTrustedRequest = 10,
                rawScore = 0,
                notes = listOf("Last trusted request is older than trust recency cutoff")
            )
        )
        printScenario("Many conditions not met", result)

        assertEquals(0, result.score)
        assertEquals(AccessDecision.DENY, result.decision)
    }

    private fun evaluate(
        devicePosture: DevicePosture = trustedDevicePosture(),
        contextSignals: ContextSignals = trustedContextSignals(),
        behaviorSignals: BehaviorSignals = trustedBehaviorSignals(),
        trustRecencySignals: TrustRecencySignals = trustedRecencySignals()
    ): ScenarioResult {
        val score = trustScoreEngine().calculate(
            TrustInputs(
                identityAuthenticated = true,
                multiFactorSatisfied = true,
                devicePosture = devicePosture,
                contextSignals = contextSignals,
                behaviorSignals = behaviorSignals,
                trustRecencySignals = trustRecencySignals
            )
        )
        return ScenarioResult(
            score = score.total,
            decision = PolicyEvaluator().evaluate(score).decision,
            device = score.device,
            context = score.context,
            behavior = score.behavior,
            trustRecency = score.trustRecency
        )
    }

    private fun trustedDevicePosture(): DevicePosture {
        return DevicePosture(
            isRegistered = true,
            passesIntegrity = true,
            osVersionRecentEnough = true,
            secureLockEnabled = true,
            hardwareBackedKeysAvailable = true,
            applicationChecksumMatches = true,
            applicationChecksumSha256 = "AA",
            expectedApplicationChecksumSha256 = "AA",
            permissionPolicyMatches = true,
            missingRequiredPermissions = emptyList(),
            missingRuntimePermissions = emptyList(),
            extraDeclaredPermissions = emptyList(),
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
            countryAllowed = true,
            countryIsoCode = "EE",
            notes = emptyList()
        )
    }

    private fun trustedBehaviorSignals(): BehaviorSignals = BehaviorMonitor().collect(emptyList(), now)

    private fun suspiciousRequestSignals(): BehaviorSignals {
        val sessions = listOf(
            SessionRecord("1", "requester", "target", now - 10_000L, 0, AccessDecision.DENY.name),
            SessionRecord("2", "requester", "target", now - 20_000L, 0, AccessDecision.DENY.name),
            SessionRecord("3", "requester", "target", now - 30_000L, 0, AccessDecision.REQUIRE_STEP_UP.name),
            SessionRecord("4", "requester", "target", now - 40_000L, 90, AccessDecision.ALLOW_PRECISE.name),
            SessionRecord("5", "requester", "target", now - 50_000L, 80, AccessDecision.ALLOW_APPROXIMATE.name)
        )
        return BehaviorMonitor().collect(sessions, now)
    }

    private fun trustedRecencySignals(): TrustRecencySignals {
        return TrustRecencySignals(
            lastTrustedRequestEpochMs = now,
            monthsSinceLastTrustedRequest = 0,
            rawScore = 10,
            notes = emptyList()
        )
    }

    private fun trustScoreEngine(): TrustScoreEngine {
        val points = ZtaConfig().resolvedTrustSignalPoints()
        return TrustScoreEngine(
            registeredDevicePoints = points.registeredDevice,
            deviceIntegrityPoints = points.deviceIntegrity,
            osVersionPoints = points.osVersion,
            hardwareBackedKeysPoints = points.hardwareBackedKeys,
            secureLockPoints = points.secureLock,
            applicationChecksumPoints = points.applicationChecksum,
            permissionPolicyPoints = points.permissionPolicy,
            trustedNetworkPoints = points.trustedNetwork,
            expectedHoursPoints = points.expectedHours,
            requestFreshnessPoints = points.requestFreshness,
            expectedCountryPoints = points.expectedCountry,
            normalRequestRatePoints = points.normalRequestRate,
            noRepeatedFailuresPoints = points.noRepeatedFailures,
            plausibleMovementPoints = points.plausibleMovement,
            trustRecencyPoints = points.trustRecency
        )
    }

    private data class ScenarioResult(
        val score: Int,
        val decision: AccessDecision,
        val device: Double,
        val context: Double,
        val behavior: Double,
        val trustRecency: Double
    )

    private fun printScenario(name: String, result: ScenarioResult) {
        println(
            "SCENARIO_SCORE | $name | total=${result.score} | decision=${result.decision} | " +
                "device=${"%.2f".format(result.device)} | context=${"%.2f".format(result.context)} | " +
                "behavior=${"%.2f".format(result.behavior)} | trustRecency=${"%.2f".format(result.trustRecency)}"
        )
    }
}
