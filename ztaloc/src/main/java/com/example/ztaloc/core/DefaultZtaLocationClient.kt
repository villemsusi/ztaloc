package com.example.ztaloc.core

import android.app.Activity
import android.content.Context
import com.example.ztaloc.api.*
import com.example.ztaloc.auth.DeviceAuthenticator
import com.example.ztaloc.behavior.BehaviorMonitor
import com.example.ztaloc.context.ContextSignalsCollector
import com.example.ztaloc.crypto.HybridEncryptedEnvelope
import com.example.ztaloc.crypto.TransportCrypto
import com.example.ztaloc.data.LocalStore
import com.example.ztaloc.data.LocalUser
import com.example.ztaloc.data.SessionRecord
import com.example.ztaloc.device.DevicePostureCollector
import com.example.ztaloc.location.LocationProvider
import com.example.ztaloc.location.LocationTransformer
import com.example.ztaloc.policy.PolicyEvaluator
import com.example.ztaloc.policy.TrustInputs
import com.example.ztaloc.policy.TrustScoreEngine
import com.example.ztaloc.protocol.RequestClaims
import com.example.ztaloc.protocol.ResponseClaims
import com.example.ztaloc.protocol.UnsignedRequestClaims
import com.example.ztaloc.protocol.UnsignedResponseClaims
import kotlinx.serialization.encodeToString
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.json.Json

class DefaultZtaLocationClient(
    private val context: Context,
    private val config: ZtaConfig = ZtaConfig()
) : ZtaLocationClient {
    private val json = Json { ignoreUnknownKeys = true; encodeDefaults = true }
    private val store = LocalStore(context, config.semanticLabelRadiusMeters)
    private val crypto = TransportCrypto()
    private val devicePostureCollector = DevicePostureCollector(context)
    private val contextSignalsCollector = ContextSignalsCollector(
        context = context,
        knownHoursStart = config.knownHoursStart,
        knownHoursEnd = config.knownHoursEnd,
        requestFreshnessMs = config.requestFreshnessMs
    )
    private val behaviorMonitor = BehaviorMonitor()
    private val trustScoreEngine = TrustScoreEngine()
    private val policyEvaluator = PolicyEvaluator(
        preciseThreshold = config.preciseThreshold,
        approximateThreshold = config.approximateThreshold,
        semanticThreshold = config.semanticThreshold,
        minimumCategoryScore = config.minimumCategoryScore
    )
    private val locationProvider = LocationProvider(context)
    private val transformer = LocationTransformer(config.approximateMaxOffsetKm)
    private val deviceAuthenticator = DeviceAuthenticator()

    companion object {
        private const val SIGNING_ALIAS = "zta_signing"
        private const val ENCRYPTION_ALIAS = "zta_encryption"
    }

    override suspend fun setupUser(userId: String, displayName: String?): Result<SetupResult> = runCatching {
        val existingUser = store.getUser()

        if (existingUser != null && existingUser.userId == userId && existingUser.deviceId != null && existingUser.registeredAtEpochMs != null) {
            return@runCatching SetupResult(
                userId = existingUser.userId,
                deviceId = requireNotNull(existingUser.deviceId),
                alreadyInitialized = true,
                message = "User and device already initialized"
            )
        }
        if (existingUser != null && existingUser.userId != userId) {
            clearLocalUserState()
        }

        crypto.ensureSigningKey(SIGNING_ALIAS)
        crypto.ensureEncryptionKey(ENCRYPTION_ALIAS)

        val deviceId = store.newDeviceId()
        val now = System.currentTimeMillis()
        store.saveUser(LocalUser(userId, displayName, deviceId, now))

        SetupResult(
            userId = userId,
            deviceId = deviceId,
            alreadyInitialized = false,
            message = "User and device setup completed"
        )
    }

    override suspend fun getDeviceRegistrationInfo(): Result<DeviceRegistrationInfo> = runCatching {
        val user = requireNotNull(store.getUser()) { "User not initialized" }
        DeviceRegistrationInfo(
            userId = user.userId,
            displayName = user.displayName,
            deviceId = requireNotNull(user.deviceId) { "Device not initialized" },
            signingPublicKeyB64 = crypto.exportPublicKey(SIGNING_ALIAS),
            encryptionPublicKeyB64 = crypto.exportPublicKey(ENCRYPTION_ALIAS),
            registeredAtEpochMs = requireNotNull(user.registeredAtEpochMs)
        )
    }
    override suspend fun upsertPairedDevice(device: PairedDevice): Result<Unit> = runCatching {
        store.upsertPairedDevice(device)
    }

    override suspend fun removePairedDevice(deviceId: String): Result<Unit> = runCatching {
        store.removePairedDevice(deviceId)
    }

    override suspend fun listPairedDevices(): Result<List<PairedDevice>> = runCatching {
        store.getPairedDevices()
    }

    override suspend fun upsertSemanticLocationLabel(label: String, latitude: Double, longitude: Double): Result<Unit> = runCatching {
        store.upsertSemanticLocationLabel(
            SemanticLocationLabel(
                label = label,
                latitude = latitude,
                longitude = longitude
            )
        )
    }

    override suspend fun removeSemanticLocationLabel(label: String): Result<Unit> = runCatching {
        store.removeSemanticLocationLabel(label)
    }

    override suspend fun listSemanticLocationLabels(): Result<List<SemanticLocationLabel>> = runCatching {
        store.getSemanticLocationLabels()
    }

    override suspend fun createLocationRequest(target: PairedDevice, activity: Activity): Result<OutgoingRequest> {
        val authentication = deviceAuthenticator.authenticateForLocationRequest(activity)
        return createLocationRequest(target, authentication)
    }

    private suspend fun createLocationRequest(
        target: PairedDevice,
        authentication: LocalAuthenticationResult
    ): Result<OutgoingRequest> = runCatching {
        check(authentication.authenticated) {
            "Location request was not authenticated: ${authentication.reason}"
        }

        val user = requireNotNull(store.getUser()) { "User not initialized" }
        val deviceId = requireNotNull(user.deviceId) { "Device not initialized" }
        val sessionId = java.util.UUID.randomUUID().toString()
        val requestEpochMs = System.currentTimeMillis()

        val requesterTrustInputs = TrustInputs(
            identityAuthenticated = authentication.authenticated,
            multiFactorSatisfied = authentication.multiFactorSatisfied,
            devicePosture = devicePostureCollector.collect(isRegistered = true),
            contextSignals = contextSignalsCollector.collect(requestEpochMs),
            behaviorSignals = behaviorMonitor.collect(store.getSessions(), requestEpochMs)
        )
        val unsignedClaims = UnsignedRequestClaims(
            sessionId = sessionId,
            requesterUserId = user.userId,
            requesterDisplayName = user.displayName,
            requesterDeviceId = deviceId,
            requesterSigningPublicKeyB64 = crypto.exportPublicKey(SIGNING_ALIAS),
            requestEpochMs = requestEpochMs,
            requesterTrustInputs = requesterTrustInputs
        )
        val signature = crypto.sign(SIGNING_ALIAS, json.encodeToString(unsignedClaims))

        val claims = RequestClaims(
            sessionId = sessionId,
            requesterUserId = user.userId,
            requesterDisplayName = user.displayName,
            requesterDeviceId = deviceId,
            requesterSigningPublicKeyB64 = crypto.exportPublicKey(SIGNING_ALIAS),
            requestEpochMs = requestEpochMs,
            requesterTrustInputs = requesterTrustInputs,
            signatureB64 = signature
        )
        val plain = json.encodeToString(claims)
        val encrypted = crypto.hybridEncrypt(target.encryptionPublicKeyB64, plain, deviceId, target.deviceId)
        val payload = json.encodeToString(encrypted)

        store.putSession(SessionRecord(sessionId, user.userId, target.userId, requestEpochMs, 0, "PENDING"))

        OutgoingRequest(
            sessionId = sessionId,
            targetUserId = target.userId,
            targetDeviceId = target.deviceId,
            payload = payload
        )
    }

    override suspend fun processIncomingRequest(requestPayload: String): Result<OutgoingResponse> = runCatching {
        val envelope = json.decodeFromString<HybridEncryptedEnvelope>(requestPayload)
        val plain = crypto.hybridDecrypt(ENCRYPTION_ALIAS, envelope)
        val claims = json.decodeFromString<RequestClaims>(plain)
        val targetUser = requireNotNull(store.getUser()) { "Target user not initialized" }
        val targetDeviceId = requireNotNull(targetUser.deviceId) { "Target device not initialized" }

        check(envelope.recipientDeviceId == targetDeviceId) {
            "Incoming request is not addressed to this device"
        }
        check(envelope.senderDeviceId == claims.requesterDeviceId) {
            "Incoming request sender device mismatch"
        }
        check(System.currentTimeMillis() - claims.requestEpochMs <= config.requestFreshnessMs) {
            "Incoming request is no longer fresh"
        }
        check(store.getString(processedRequestKey(claims.sessionId)) == null) {
            "Incoming request has already been processed"
        }

        val pairedRequester: PairedDevice = store.getPairedDevice(claims.requesterDeviceId)
            ?: error("Requester device is not paired")
        check(pairedRequester.signingPublicKeyB64 == claims.requesterSigningPublicKeyB64) {
            "Incoming request signing key does not match paired device"
        }

        val unsignedClaims = UnsignedRequestClaims(
            sessionId = claims.sessionId,
            requesterUserId = claims.requesterUserId,
            requesterDisplayName = claims.requesterDisplayName,
            requesterDeviceId = claims.requesterDeviceId,
            requesterSigningPublicKeyB64 = claims.requesterSigningPublicKeyB64,
            requestEpochMs = claims.requestEpochMs,
            requesterTrustInputs = claims.requesterTrustInputs
        )

        check(crypto.verify(pairedRequester.signingPublicKeyB64, json.encodeToString(unsignedClaims), claims.signatureB64)) {
            "Incoming request signature invalid"
        }

        store.putString(processedRequestKey(claims.sessionId), System.currentTimeMillis().toString())

        val score = trustScoreEngine.calculate(claims.requesterTrustInputs)
        val policy = policyEvaluator.evaluate(score)
        val precise = locationProvider.getCurrentPreciseLocation()
        val payload = if (precise != null && policy.exposure != LocationExposure.NONE) {
            transformer.transform(precise, policy.exposure, store.getSemanticLocationLabels())
        } else null

        val locationJson = payload?.let { json.encodeToString(it) }
        val issuedAtEpochMs = System.currentTimeMillis()
        val unsignedResponse = UnsignedResponseClaims(
            sessionId = claims.sessionId,
            targetUserId = targetUser.userId,
            targetDeviceId = targetDeviceId,
            targetSigningPublicKeyB64 = crypto.exportPublicKey(SIGNING_ALIAS),
            trustScore = score.total,
            decision = policy.decision.name,
            exposure = policy.exposure.name,
            locationJson = locationJson,
            reason = policy.rationale,
            issuedAtEpochMs = issuedAtEpochMs
        )
        val responseSignature = crypto.sign(SIGNING_ALIAS, json.encodeToString(unsignedResponse))

        val responseClaims = ResponseClaims(
            sessionId = claims.sessionId,
            targetUserId = targetUser.userId,
            targetDeviceId = targetDeviceId,
            targetSigningPublicKeyB64 = crypto.exportPublicKey(SIGNING_ALIAS),
            trustScore = score.total,
            decision = policy.decision.name,
            exposure = policy.exposure.name,
            locationJson = locationJson,
            reason = policy.rationale,
            issuedAtEpochMs = issuedAtEpochMs,
            signatureB64 = responseSignature
        )

        val plainResponse = json.encodeToString(responseClaims)
        val encryptedResponse = crypto.hybridEncrypt(
            pairedRequester.encryptionPublicKeyB64,
            plainResponse,
            targetDeviceId,
            pairedRequester.deviceId
        )

        OutgoingResponse(
            sessionId = claims.sessionId,
            requesterUserId = pairedRequester.userId,
            requesterDeviceId = pairedRequester.deviceId,
            decision = policy.decision,
            exposure = policy.exposure,
            trustScore = score.total,
            reason = policy.rationale,
            payload = json.encodeToString(encryptedResponse)
        )
    }
    override suspend fun processIncomingResponse(responsePayload: String): Result<LocationAccessResult> = runCatching {
        val envelope = json.decodeFromString<HybridEncryptedEnvelope>(responsePayload)
        val plain = crypto.hybridDecrypt(ENCRYPTION_ALIAS, envelope)
        val claims = json.decodeFromString<ResponseClaims>(plain)
        val requesterUser = requireNotNull(store.getUser()) { "Requester user not initialized" }
        val requesterDeviceId = requireNotNull(requesterUser.deviceId) { "Requester device not initialized" }

        check(envelope.recipientDeviceId == requesterDeviceId) {
            "Incoming response is not addressed to this device"
        }
        check(envelope.senderDeviceId == claims.targetDeviceId) {
            "Incoming response sender device mismatch"
        }

        val pairedTarget: PairedDevice = store.getPairedDevice(claims.targetDeviceId)
            ?: error("Target device is not paired")
        check(pairedTarget.signingPublicKeyB64 == claims.targetSigningPublicKeyB64) {
            "Incoming response signing key does not match paired device"
        }


        val unsignedResponse = UnsignedResponseClaims(
            sessionId = claims.sessionId,
            targetUserId = claims.targetUserId,
            targetDeviceId = claims.targetDeviceId,
            targetSigningPublicKeyB64 = claims.targetSigningPublicKeyB64,
            trustScore = claims.trustScore,
            decision = claims.decision,
            exposure = claims.exposure,
            locationJson = claims.locationJson,
            reason = claims.reason,
            issuedAtEpochMs = claims.issuedAtEpochMs
        )

        check(crypto.verify(pairedTarget.signingPublicKeyB64, json.encodeToString(unsignedResponse), claims.signatureB64)) {
            "Incoming response signature invalid"
        }

        val locationPayload = claims.locationJson?.takeIf { it.isNotBlank() }?.let {
            json.decodeFromString<LocationPayload>(it)
        }

        val result = LocationAccessResult(
            sessionId = claims.sessionId,
            decision = AccessDecision.valueOf(claims.decision),
            trustScore = claims.trustScore,
            exposure = LocationExposure.valueOf(claims.exposure),
            locationPayload = locationPayload,
            reason = claims.reason
        )

        store.putSession(
            SessionRecord(
                sessionId = claims.sessionId,
                requesterUserId = requireNotNull(store.getUser()).userId,
                targetUserId = claims.targetUserId,
                issuedAtEpochMs = claims.issuedAtEpochMs,
                lastTrustScore = claims.trustScore,
                lastDecision = claims.decision,
                locationLatitude = locationPayload?.latitude,
                locationLongitude = locationPayload?.longitude,
                locationTimestampEpochMs = locationPayload?.timestampEpochMs
            )
        )
        result
    }

    private suspend fun clearLocalUserState() {
        store.remove("user")
    }

    private fun processedRequestKey(sessionId: String): String = "processed_request:$sessionId"
}
