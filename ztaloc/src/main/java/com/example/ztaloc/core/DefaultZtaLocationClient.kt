package com.example.ztaloc.core

import android.content.Context
import com.example.ztaloc.api.*
import com.example.ztaloc.behavior.BehaviorMonitor
import com.example.ztaloc.context.ContextSignalsCollector
import com.example.ztaloc.crypto.CryptoManager
import com.example.ztaloc.data.LocalStore
import com.example.ztaloc.data.LocalUser
import com.example.ztaloc.data.SessionRecord
import com.example.ztaloc.device.DevicePostureCollector
import com.example.ztaloc.location.LocationProvider
import com.example.ztaloc.location.LocationTransformer
import com.example.ztaloc.network.RelayClient
import com.example.ztaloc.network.RequestEnvelope
import com.example.ztaloc.network.ResponseEnvelope
import com.example.ztaloc.policy.PolicyEvaluator
import com.example.ztaloc.policy.TrustInputs
import com.example.ztaloc.policy.TrustScoreEngine
import kotlinx.serialization.encodeToString
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.json.Json
import okhttp3.OkHttpClient
import java.util.UUID

class DefaultZtaLocationClient(
    private val context: Context,
    private val config: ZtaConfig
) : ZtaLocationClient {

    private val json = Json { ignoreUnknownKeys = true }
    private val store = LocalStore(context)
    private val crypto = CryptoManager(context)
    private val devicePostureCollector = DevicePostureCollector(context)
    private val contextSignalsCollector = ContextSignalsCollector(
        context,
        config.trustedWifiSsids,
        config.knownHoursStart,
        config.knownHoursEnd
    )
    private val behaviorMonitor = BehaviorMonitor()
    private val trustScoreEngine = TrustScoreEngine()
    private val policyEvaluator = PolicyEvaluator(config)
    private val locationProvider = LocationProvider(context)
    private val transformer = LocationTransformer()
    private val relayClient = RelayClient(OkHttpClient(), config.relayBaseUrl.toString().trimEnd('/'))

    companion object {
        private const val SIGNING_ALIAS = "zta_signing"
        private const val PAYLOAD_ALIAS = "zta_payload"
    }

    override suspend fun initializeUser(userId: String, displayName: String?): Result<Unit> = runCatching {
        crypto.ensureSigningKey(SIGNING_ALIAS)
        crypto.ensureAesKey(PAYLOAD_ALIAS)
        val existing = store.getUser()
        store.saveUser(
            LocalUser(
                userId = userId,
                displayName = displayName,
                deviceId = existing?.deviceId,
                registeredAtEpochMs = existing?.registeredAtEpochMs
            )
        )
    }

    override suspend fun registerCurrentDevice(): Result<DeviceRegistrationResult> = runCatching {
        val user = requireNotNull(store.getUser()) { "User not initialized" }
        crypto.ensureSigningKey(SIGNING_ALIAS)
        val deviceId = user.deviceId ?: store.newDeviceId()
        val registeredAt = System.currentTimeMillis()
        val publicKeyB64 = crypto.getPublicKey(SIGNING_ALIAS)

        val unsignedPayload = json.encodeToString(
            mapOf(
                "userId" to user.userId,
                "displayName" to (user.displayName ?: ""),
                "deviceId" to deviceId,
                "platform" to "android",
                "appPackageName" to config.appPackageName,
                "appVersion" to config.appVersion,
                "publicSigningKeyB64" to publicKeyB64,
                "registeredAtEpochMs" to registeredAt.toString()
            )
        )
        val signature = crypto.sign(SIGNING_ALIAS, unsignedPayload)

        val relayResponse = relayClient.registerDevice(
            com.example.ztaloc.network.DeviceRegistrationPayload(
                userId = user.userId,
                displayName = user.displayName,
                deviceId = deviceId,
                platform = "android",
                appPackageName = config.appPackageName,
                appVersion = config.appVersion,
                publicSigningKeyB64 = publicKeyB64,
                registeredAtEpochMs = registeredAt,
                signatureB64 = signature
            )
        ).getOrThrow()

        if (!relayResponse.accepted) error(relayResponse.message)

        store.saveUser(user.copy(deviceId = deviceId, registeredAtEpochMs = registeredAt))
        relayResponse.serverAssignedRegistrationId?.let { store.putString("registration_id", it) }
        store.putString("public_signing_key_b64", publicKeyB64)

        DeviceRegistrationResult(
            userId = user.userId,
            deviceId = deviceId,
            registrationId = relayResponse.serverAssignedRegistrationId,
            registeredAtEpochMs = registeredAt,
            publicSigningKeyB64 = publicKeyB64,
            message = relayResponse.message
        )
    }

    override suspend fun requestLocation(targetUserId: String): Result<LocationAccessResult> = runCatching {
        val user = requireNotNull(store.getUser()) { "User not initialized" }
        val deviceId = requireNotNull(user.deviceId) { "Current device not registered" }
        val sessionId = UUID.randomUUID().toString()
        val requestEpochMs = System.currentTimeMillis()
        val signedPayload = json.encodeToString(
            mapOf(
                "sessionId" to sessionId,
                "requesterUserId" to user.userId,
                "targetUserId" to targetUserId,
                "requesterDeviceId" to deviceId,
                "requestEpochMs" to requestEpochMs.toString(),
                "identityAuthenticated" to "true",
                "multiFactorSatisfied" to "true"
            )
        )
        val signature = crypto.sign(SIGNING_ALIAS, signedPayload)
        val envelope = RequestEnvelope(
            sessionId = sessionId,
            requesterUserId = user.userId,
            targetUserId = targetUserId,
            requesterDeviceId = deviceId,
            requestEpochMs = requestEpochMs,
            identityAuthenticated = true,
            multiFactorSatisfied = true,
            signedPayload = signedPayload,
            signatureB64 = signature
        )
        relayClient.sendRequest(envelope).getOrThrow()
        store.putSession(SessionRecord(sessionId, user.userId, targetUserId, requestEpochMs, 0, "PENDING"))
        LocationAccessResult(
            sessionId = sessionId,
            decision = AccessDecision.REQUIRE_STEP_UP,
            trustScore = 0,
            exposure = LocationExposure.NONE,
            locationPayload = null,
            reason = "Request submitted to relay; await target response"
        )
    }

    override suspend fun respondToLocationRequest(requestEnvelopeJson: String): Result<String> = runCatching {
        val request = json.decodeFromString<RequestEnvelope>(requestEnvelopeJson)
        val localUser = requireNotNull(store.getUser()) { "User not initialized" }
        check(localUser.userId == request.targetUserId) { "This request is not addressed to current user" }
        val registered = request.requesterDeviceId.isNotBlank()
        val posture = devicePostureCollector.collect(isRegistered = registered)
        val contextSignals = contextSignalsCollector.collect(request.requestEpochMs)
        val behaviorSignals = behaviorMonitor.collect()
        val inputs = TrustInputs(
            identityAuthenticated = request.identityAuthenticated,
            multiFactorSatisfied = request.multiFactorSatisfied,
            devicePosture = posture,
            contextSignals = contextSignals,
            behaviorSignals = behaviorSignals
        )
        val score = trustScoreEngine.calculate(inputs)
        val policy = policyEvaluator.evaluate(score.total)
        val precise = locationProvider.getCurrentPreciseLocation()
        val payload = if (precise != null && policy.exposure != LocationExposure.NONE) {
            transformer.transform(precise, policy.exposure)
        } else null
        val responseModel = LocationAccessResult(
            sessionId = request.sessionId,
            decision = policy.decision,
            trustScore = score.total,
            exposure = policy.exposure,
            locationPayload = payload,
            reason = policy.rationale
        )
        val encryptedPayload = crypto.encrypt(PAYLOAD_ALIAS, json.encodeToString(responseModel))
        val responseJson = json.encodeToString(encryptedPayload)
        val signature = crypto.sign(SIGNING_ALIAS, responseJson)
        val envelope = ResponseEnvelope(
            sessionId = request.sessionId,
            targetUserId = localUser.userId,
            encryptedPayloadJson = responseJson,
            signatureB64 = signature,
            issuedAtEpochMs = System.currentTimeMillis()
        )
        relayClient.sendResponse(envelope).getOrThrow()
        json.encodeToString(envelope)
    }

    override suspend fun reevaluateSession(sessionId: String): Result<LocationAccessResult> = runCatching {
        val session = requireNotNull(store.getSession(sessionId)) { "Session not found" }
        val user = requireNotNull(store.getUser()) { "User not initialized" }
        val posture = devicePostureCollector.collect(isRegistered = user.deviceId != null)
        val contextSignals = contextSignalsCollector.collect(session.issuedAtEpochMs)
        val behaviorSignals = behaviorMonitor.collect(recentFailures = 0, recentBurstRequests = 0)
        val inputs = TrustInputs(
            identityAuthenticated = true,
            multiFactorSatisfied = true,
            devicePosture = posture,
            contextSignals = contextSignals,
            behaviorSignals = behaviorSignals
        )
        val score = trustScoreEngine.calculate(inputs)
        val policy = policyEvaluator.evaluate(score.total)
        val result = LocationAccessResult(
            sessionId = sessionId,
            decision = policy.decision,
            trustScore = score.total,
            exposure = policy.exposure,
            locationPayload = null,
            reason = "Re-evaluated during active session"
        )
        store.putSession(session.copy(lastTrustScore = score.total, lastDecision = policy.decision.name))
        result
    }
}
