package com.example.ztaloc.core

import android.app.Activity
import android.content.Context
import com.example.ztaloc.api.*
import com.example.ztaloc.auth.DeviceAuthenticator
import com.example.ztaloc.behavior.BehaviorMonitor
import com.example.ztaloc.context.ContextSignalsCollector
import com.example.ztaloc.crypto.HybridEncryptedEnvelope
import com.example.ztaloc.crypto.TransportCrypto
import com.example.ztaloc.data.AuditLogEntry
import com.example.ztaloc.data.LocalStore
import com.example.ztaloc.data.LocalUser
import com.example.ztaloc.data.SessionRecord
import com.example.ztaloc.device.DevicePostureCollector
import com.example.ztaloc.location.LocationProvider
import com.example.ztaloc.location.LocationTransformer
import com.example.ztaloc.policy.PolicyEvaluator
import com.example.ztaloc.policy.TrustInputs
import com.example.ztaloc.policy.TrustRecencySignals
import com.example.ztaloc.policy.TrustScoreEngine
import com.example.ztaloc.protocol.CustomPayloadClaims
import com.example.ztaloc.protocol.RequestClaims
import com.example.ztaloc.protocol.ResponseClaims
import com.example.ztaloc.protocol.UnsignedCustomPayloadClaims
import com.example.ztaloc.protocol.UnsignedRequestClaims
import com.example.ztaloc.protocol.UnsignedResponseClaims
import kotlinx.serialization.encodeToString
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.json.Json
import android.util.Base64
import java.nio.charset.StandardCharsets
import java.security.MessageDigest

class DefaultZtaLocationClient(
    private val context: Context,
    private val config: ZtaConfig = ZtaConfig()
) : ZtaLocationClient {
    private val json = Json { ignoreUnknownKeys = true; encodeDefaults = true }
    private val store = LocalStore(context)
    private val crypto = TransportCrypto()
    private val devicePostureCollector = DevicePostureCollector(
        context = context,
        expectedPackageName = config.appPackageName,
        expectedApplicationChecksumSha256 = config.applicationChecksumSha256,
        requiredPermissions = config.requiredPermissions,
        allowedPermissions = config.allowedPermissions,
        enablePlayIntegrityChecks = config.enablePlayIntegrityChecks
    )
    private val contextSignalsCollector = ContextSignalsCollector(
        context = context,
        knownHoursStart = config.knownHoursStart,
        knownHoursEnd = config.knownHoursEnd,
        requestFreshnessMs = config.requestFreshnessMs,
        expectedCountryIsoCodes = config.expectedCountryIsoCodes,
        trustedWifiSsids = config.trustedWifiSsids
    )
    private val behaviorMonitor = BehaviorMonitor()
    private val trustSignalPoints = config.resolvedTrustSignalPoints()
    private val trustScoreEngine = TrustScoreEngine(
        registeredDevicePoints = trustSignalPoints.registeredDevice,
        deviceIntegrityPoints = trustSignalPoints.deviceIntegrity,
        osVersionPoints = trustSignalPoints.osVersion,
        hardwareBackedKeysPoints = trustSignalPoints.hardwareBackedKeys,
        secureLockPoints = trustSignalPoints.secureLock,
        applicationChecksumPoints = trustSignalPoints.applicationChecksum,
        permissionPolicyPoints = trustSignalPoints.permissionPolicy,
        trustedNetworkPoints = trustSignalPoints.trustedNetwork,
        expectedHoursPoints = trustSignalPoints.expectedHours,
        requestFreshnessPoints = trustSignalPoints.requestFreshness,
        expectedCountryPoints = trustSignalPoints.expectedCountry,
        normalRequestRatePoints = trustSignalPoints.normalRequestRate,
        noRepeatedFailuresPoints = trustSignalPoints.noRepeatedFailures,
        plausibleMovementPoints = trustSignalPoints.plausibleMovement,
        trustRecencyPoints = trustSignalPoints.trustRecency
    )
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
        private const val TRUST_RECENCY_MONTH_MS = 30L * 24L * 60L * 60L * 1000L
        private val TRUSTED_DECISIONS = setOf(
            AccessDecision.ALLOW_SEMANTIC.name,
            AccessDecision.ALLOW_APPROXIMATE.name,
            AccessDecision.ALLOW_PRECISE.name
        )
    }

    override suspend fun setupUser(userId: String, displayName: String?): Result<SetupResult> = runCatching {
        val existingUser = store.getUser()

        crypto.ensureSigningKey(SIGNING_ALIAS)
        crypto.ensureEncryptionKey(ENCRYPTION_ALIAS)

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

        val deviceId = store.newDeviceId()
        val now = System.currentTimeMillis()
        store.saveUser(LocalUser(userId, displayName, deviceId, now))
        appendAuditLog("USER_SETUP", userId, deviceId, null, "SUCCESS")

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

    override suspend fun getKeyLifecycleStatus(): Result<KeyLifecycleStatus> = runCatching {
        val user = requireNotNull(store.getUser()) { "User not initialized" }
        lifecycleStatus(user)
    }

    override suspend fun rotateLocalKeys(reason: String?): Result<KeyRotationResult> = runCatching {
        val user = requireNotNull(store.getUser()) { "User not initialized" }
        val previousSigningPublicKey = crypto.exportPublicKey(SIGNING_ALIAS)
        val previousEncryptionPublicKey = crypto.exportPublicKey(ENCRYPTION_ALIAS)
        val previousFingerprint = crypto.pairingFingerprint(previousSigningPublicKey, previousEncryptionPublicKey)

        crypto.rotateSigningKey(SIGNING_ALIAS)
        crypto.rotateEncryptionKey(ENCRYPTION_ALIAS)

        val now = System.currentTimeMillis()
        val updatedUser = user.copy(
            keyVersion = user.keyVersion + 1,
            keysCreatedAtEpochMs = user.keysCreatedAtEpochMs ?: user.registeredAtEpochMs ?: now,
            keysRotatedAtEpochMs = now,
            keyRotationReason = reason
        )
        store.saveUser(updatedUser)
        val status = lifecycleStatus(updatedUser)
        appendAuditLog(
            eventType = "LOCAL_KEYS_ROTATED",
            subjectUserId = updatedUser.userId,
            subjectDeviceId = updatedUser.deviceId,
            sessionId = null,
            result = "SUCCESS",
            metadata = mapOf(
                "keyVersion" to updatedUser.keyVersion.toString(),
                "previousPairingFingerprint" to previousFingerprint,
                "newPairingFingerprint" to status.pairingFingerprint,
                "reason" to (reason ?: "unspecified")
            )
        )

        KeyRotationResult(
            registrationInfo = registrationInfo(updatedUser),
            lifecycleStatus = status,
            previousPairingFingerprint = previousFingerprint,
            message = "Local keys rotated. Previously paired devices must register the new public keys."
        )
    }

    override suspend fun clearLocalKeyMaterial(): Result<Unit> = runCatching {
        val user = store.getUser()
        appendAuditLog(
            eventType = "LOCAL_KEY_MATERIAL_CLEARED",
            subjectUserId = user?.userId,
            subjectDeviceId = user?.deviceId,
            sessionId = null,
            result = "SUCCESS"
        )
        crypto.deleteKey(SIGNING_ALIAS)
        crypto.deleteKey(ENCRYPTION_ALIAS)
        store.clearLocalIdentityAndPairings()
    }

    override suspend fun upsertPairedDevice(device: PairedDevice, expectedPairingFingerprint: String): Result<Unit> = runCatching {
        validatePairingKeys(device)
        val actualFingerprint = pairingFingerprint(device).getOrThrow()
        require(actualFingerprint.equals(normalizeFingerprint(expectedPairingFingerprint), ignoreCase = true)) {
            "Pairing fingerprint mismatch"
        }
        store.upsertPairedDevice(device)
        appendAuditLog(
            eventType = "PAIRED_DEVICE_UPSERTED",
            subjectUserId = device.userId,
            subjectDeviceId = device.deviceId,
            sessionId = null,
            result = "SUCCESS",
            metadata = mapOf("pairingFingerprint" to actualFingerprint)
        )
    }

    override suspend fun pairingFingerprint(device: PairedDevice): Result<String> = runCatching {
        validatePairingKeys(device)
        crypto.pairingFingerprint(device.signingPublicKeyB64, device.encryptionPublicKeyB64)
    }

    override suspend fun removePairedDevice(deviceId: String): Result<Unit> = runCatching {
        store.removePairedDevice(deviceId)
        appendAuditLog(
            eventType = "PAIRED_DEVICE_REVOKED",
            subjectUserId = null,
            subjectDeviceId = deviceId,
            sessionId = null,
            result = "SUCCESS"
        )
    }

    override suspend fun listPairedDevices(): Result<List<PairedDevice>> = runCatching {
        store.getPairedDevices()
    }

    override suspend fun upsertSemanticLocationLabel(
        label: String,
        latitude: Double,
        longitude: Double,
        radiusMeters: Double?
    ): Result<Unit> = runCatching {
        store.upsertSemanticLocationLabel(
            SemanticLocationLabel(
                label = label,
                latitude = latitude,
                longitude = longitude,
                radiusMeters = radiusMeters ?: config.semanticLabelRadiusMeters
            )
        )
    }

    override suspend fun removeSemanticLocationLabel(label: String): Result<Unit> = runCatching {
        store.removeSemanticLocationLabel(label)
    }

    override suspend fun listSemanticLocationLabels(): Result<List<SemanticLocationLabel>> = runCatching {
        store.getSemanticLocationLabels()
    }

    override suspend fun listSecureAuditLog(): Result<List<SecureAuditLogEntry>> = runCatching {
        store.getAuditLogEntries().map { entry ->
            SecureAuditLogEntry(
                sequence = entry.sequence,
                eventType = entry.eventType,
                subjectUserId = entry.subjectUserId,
                subjectDeviceId = entry.subjectDeviceId,
                sessionId = entry.sessionId,
                result = entry.result,
                issuedAtEpochMs = entry.issuedAtEpochMs,
                metadata = entry.metadata,
                previousHashB64 = entry.previousHashB64,
                entryHashB64 = entry.entryHashB64,
                signatureB64 = entry.signatureB64
            )
        }
    }

    override suspend fun createLocationRequest(target: PairedDevice, activity: Activity): Result<OutgoingRequest> {
        val authentication = deviceAuthenticator.authenticateForLocationRequest(activity)
        return createLocationRequest(target, authentication)
    }

    internal suspend fun createLocationRequestForTesting(
        target: PairedDevice,
        authentication: LocalAuthenticationResult
    ): Result<OutgoingRequest> = createLocationRequest(target, authentication)

    private suspend fun createLocationRequest(
        target: PairedDevice,
        authentication: LocalAuthenticationResult
    ): Result<OutgoingRequest> = runCatching {
        val timer = WorkflowTimer("createLocationRequest")
        val existingUser = store.getUser()
        appendAuditLog(
            eventType = "AUTHENTICATION_ATTEMPT",
            subjectUserId = existingUser?.userId,
            subjectDeviceId = existingUser?.deviceId,
            sessionId = null,
            result = if (authentication.authenticated) "SUCCESS" else "FAILURE",
            metadata = mapOf("reason" to authentication.reason)
        )
        check(authentication.authenticated) {
            "Location request was not authenticated: ${authentication.reason}"
        }
        timer.mark("authentication")

        val user = requireNotNull(store.getUser()) { "User not initialized" }
        val deviceId = requireNotNull(user.deviceId) { "Device not initialized" }
        val pairedTarget = requirePairedDevice(target.deviceId)
        check(pairedTarget == target) {
            "Target device details do not match the paired device record"
        }
        val sessionId = java.util.UUID.randomUUID().toString()
        val requestEpochMs = System.currentTimeMillis()
        timer.mark("load_local_user")

        val requesterTrustInputs = TrustInputs(
            identityAuthenticated = authentication.authenticated,
            multiFactorSatisfied = authentication.multiFactorSatisfied,
            devicePosture = devicePostureCollector.collect(isRegistered = true),
            contextSignals = contextSignalsCollector.collect(requestEpochMs),
            behaviorSignals = behaviorMonitor.collect(store.getSessions(), requestEpochMs),
            trustRecencySignals = collectTrustRecency(
                sessions = store.getSessions(),
                requestEpochMs = requestEpochMs,
                requesterUserId = user.userId,
                targetUserId = target.userId,
                fallbackTrustedEpochMs = target.pairedAtEpochMs
            )
        )
        timer.mark("collect_trust_inputs")
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
        timer.mark("sign_request_claims")

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
        timer.mark("encrypt_request_payload")

        store.putSession(SessionRecord(sessionId, user.userId, target.userId, requestEpochMs, 0, "PENDING"))
        timer.mark("persist_pending_session")

        val request = OutgoingRequest(
            sessionId = sessionId,
            targetUserId = target.userId,
            targetDeviceId = target.deviceId,
            payload = payload
        )
        appendAuditLog(
            eventType = "LOCATION_REQUEST_CREATED",
            subjectUserId = user.userId,
            subjectDeviceId = deviceId,
            sessionId = sessionId,
            result = "PENDING",
            metadata = mapOf("targetDeviceId" to target.deviceId)
        )
        ZtaTiming.lastCreateLocationRequest = timer.finish()
        request
    }

    override suspend fun processIncomingRequest(requestPayload: String): Result<OutgoingResponse> = runCatching {
        val timer = WorkflowTimer("processIncomingRequest")
        val envelope = json.decodeFromString<HybridEncryptedEnvelope>(requestPayload)
        val plain = crypto.hybridDecrypt(ENCRYPTION_ALIAS, envelope)
        val claims = json.decodeFromString<RequestClaims>(plain)
        timer.mark("decrypt_request_payload")
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
        timer.mark("validate_request")

        store.putString(processedRequestKey(claims.sessionId), System.currentTimeMillis().toString())
        timer.mark("persist_replay_marker")

        val targetComputedTrustInputs = claims.requesterTrustInputs.copy(
            trustRecencySignals = collectTrustRecency(
                sessions = store.getSessions(),
                requestEpochMs = claims.requestEpochMs,
                requesterUserId = claims.requesterUserId,
                targetUserId = targetUser.userId,
                fallbackTrustedEpochMs = pairedRequester.pairedAtEpochMs
            )
        )
        val score = trustScoreEngine.calculate(targetComputedTrustInputs)
        val policy = policyEvaluator.evaluate(score)
        appendAuditLog(
            eventType = "POLICY_DECISION",
            subjectUserId = claims.requesterUserId,
            subjectDeviceId = claims.requesterDeviceId,
            sessionId = claims.sessionId,
            result = policy.decision.name,
            metadata = mapOf(
                "trustScore" to score.total.toString(),
                "exposure" to policy.exposure.name,
                "reason" to policy.rationale
            )
        )
        timer.mark("evaluate_policy")
        val precise = locationProvider.getCurrentPreciseLocation()
        val payload = if (precise != null && policy.exposure != LocationExposure.NONE) {
            transformer.transform(precise, policy.exposure, store.getSemanticLocationLabels())
        } else null
        timer.mark("collect_transform_location")

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
        timer.mark("sign_response_claims")

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
        timer.mark("encrypt_response_payload")

        store.putSession(
            SessionRecord(
                sessionId = claims.sessionId,
                requesterUserId = claims.requesterUserId,
                targetUserId = targetUser.userId,
                issuedAtEpochMs = issuedAtEpochMs,
                lastTrustScore = score.total,
                lastDecision = policy.decision.name,
                locationLatitude = payload?.latitude,
                locationLongitude = payload?.longitude,
                locationTimestampEpochMs = payload?.timestampEpochMs
            )
        )
        timer.mark("persist_response_session")

        val response = OutgoingResponse(
            sessionId = claims.sessionId,
            requesterUserId = pairedRequester.userId,
            requesterDeviceId = pairedRequester.deviceId,
            decision = policy.decision,
            exposure = policy.exposure,
            trustScore = score.total,
            reason = policy.rationale,
            payload = json.encodeToString(encryptedResponse)
        )
        appendAuditLog(
            eventType = "LOCATION_RESPONSE_CREATED",
            subjectUserId = claims.requesterUserId,
            subjectDeviceId = claims.requesterDeviceId,
            sessionId = claims.sessionId,
            result = policy.decision.name
        )
        ZtaTiming.lastProcessIncomingRequest = timer.finish()
        response
    }
    override suspend fun processIncomingResponse(responsePayload: String): Result<LocationAccessResult> = runCatching {
        val timer = WorkflowTimer("processIncomingResponse")
        val envelope = json.decodeFromString<HybridEncryptedEnvelope>(responsePayload)
        val plain = crypto.hybridDecrypt(ENCRYPTION_ALIAS, envelope)
        val claims = json.decodeFromString<ResponseClaims>(plain)
        timer.mark("decrypt_response_payload")
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
        timer.mark("validate_response")

        val locationPayload = claims.locationJson?.takeIf { it.isNotBlank() }?.let {
            json.decodeFromString<LocationPayload>(it)
        }
        timer.mark("decode_location_payload")

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
        timer.mark("persist_final_session")
        appendAuditLog(
            eventType = "LOCATION_RESPONSE_PROCESSED",
            subjectUserId = requesterUser.userId,
            subjectDeviceId = requesterDeviceId,
            sessionId = claims.sessionId,
            result = claims.decision
        )
        ZtaTiming.lastProcessIncomingResponse = timer.finish()
        result
    }

    override suspend fun encryptPayload(target: PairedDevice, plaintext: String): Result<String> = runCatching {
        val user = requireNotNull(store.getUser()) { "User not initialized" }
        val deviceId = requireNotNull(user.deviceId) { "Device not initialized" }
        val pairedTarget = requirePairedDevice(target.deviceId)
        check(pairedTarget == target) {
            "Target device details do not match the paired device record"
        }
        val issuedAtEpochMs = System.currentTimeMillis()
        val unsignedClaims = UnsignedCustomPayloadClaims(
            sessionId = java.util.UUID.randomUUID().toString(),
            senderUserId = user.userId,
            senderDeviceId = deviceId,
            senderSigningPublicKeyB64 = crypto.exportPublicKey(SIGNING_ALIAS),
            recipientDeviceId = target.deviceId,
            issuedAtEpochMs = issuedAtEpochMs,
            payload = plaintext
        )
        val claims = CustomPayloadClaims(
            sessionId = unsignedClaims.sessionId,
            senderUserId = unsignedClaims.senderUserId,
            senderDeviceId = unsignedClaims.senderDeviceId,
            senderSigningPublicKeyB64 = unsignedClaims.senderSigningPublicKeyB64,
            recipientDeviceId = unsignedClaims.recipientDeviceId,
            issuedAtEpochMs = unsignedClaims.issuedAtEpochMs,
            payload = unsignedClaims.payload,
            signatureB64 = crypto.sign(SIGNING_ALIAS, json.encodeToString(unsignedClaims))
        )
        val encrypted = crypto.hybridEncrypt(
            recipientEncryptionPublicKeyB64 = target.encryptionPublicKeyB64,
            plaintext = json.encodeToString(claims),
            senderDeviceId = deviceId,
            recipientDeviceId = target.deviceId
        )
        json.encodeToString(encrypted)
    }

    override suspend fun decryptPayload(encryptedPayload: String): Result<String> = runCatching {
        val user = requireNotNull(store.getUser()) { "User not initialized" }
        val deviceId = requireNotNull(user.deviceId) { "Device not initialized" }
        val envelope = json.decodeFromString<HybridEncryptedEnvelope>(encryptedPayload)
        check(envelope.recipientDeviceId == deviceId) {
            "Encrypted payload is not addressed to this device"
        }
        val plain = crypto.hybridDecrypt(ENCRYPTION_ALIAS, envelope)
        val claims = json.decodeFromString<CustomPayloadClaims>(plain)
        check(envelope.senderDeviceId == claims.senderDeviceId) {
            "Encrypted payload sender device mismatch"
        }
        check(claims.recipientDeviceId == deviceId) {
            "Custom payload claims are not addressed to this device"
        }
        check(System.currentTimeMillis() - claims.issuedAtEpochMs <= config.requestFreshnessMs) {
            "Encrypted payload is no longer fresh"
        }
        check(store.getString(processedCustomPayloadKey(claims.sessionId)) == null) {
            "Encrypted payload has already been processed"
        }
        val pairedSender = requirePairedDevice(claims.senderDeviceId)
        check(pairedSender.signingPublicKeyB64 == claims.senderSigningPublicKeyB64) {
            "Custom payload signing key does not match paired device"
        }

        val unsignedClaims = UnsignedCustomPayloadClaims(
            sessionId = claims.sessionId,
            senderUserId = claims.senderUserId,
            senderDeviceId = claims.senderDeviceId,
            senderSigningPublicKeyB64 = claims.senderSigningPublicKeyB64,
            recipientDeviceId = claims.recipientDeviceId,
            issuedAtEpochMs = claims.issuedAtEpochMs,
            payload = claims.payload
        )
        check(crypto.verify(pairedSender.signingPublicKeyB64, json.encodeToString(unsignedClaims), claims.signatureB64)) {
            "Custom payload signature invalid"
        }
        store.putString(processedCustomPayloadKey(claims.sessionId), System.currentTimeMillis().toString())
        claims.payload
    }

    private suspend fun clearLocalUserState() {
        store.remove("user")
    }

    private fun registrationInfo(user: LocalUser): DeviceRegistrationInfo {
        return DeviceRegistrationInfo(
            userId = user.userId,
            displayName = user.displayName,
            deviceId = requireNotNull(user.deviceId) { "Device not initialized" },
            signingPublicKeyB64 = crypto.exportPublicKey(SIGNING_ALIAS),
            encryptionPublicKeyB64 = crypto.exportPublicKey(ENCRYPTION_ALIAS),
            registeredAtEpochMs = requireNotNull(user.registeredAtEpochMs) { "Device not initialized" }
        )
    }

    private fun lifecycleStatus(user: LocalUser): KeyLifecycleStatus {
        val signingPublicKey = crypto.exportPublicKey(SIGNING_ALIAS)
        val encryptionPublicKey = crypto.exportPublicKey(ENCRYPTION_ALIAS)
        return KeyLifecycleStatus(
            userId = user.userId,
            deviceId = requireNotNull(user.deviceId) { "Device not initialized" },
            signingPublicKeyB64 = signingPublicKey,
            encryptionPublicKeyB64 = encryptionPublicKey,
            keyVersion = user.keyVersion,
            createdAtEpochMs = user.keysCreatedAtEpochMs ?: requireNotNull(user.registeredAtEpochMs),
            rotatedAtEpochMs = user.keysRotatedAtEpochMs,
            rotationReason = user.keyRotationReason,
            pairingFingerprint = crypto.pairingFingerprint(signingPublicKey, encryptionPublicKey)
        )
    }

    private fun processedRequestKey(sessionId: String): String = "processed_request:$sessionId"

    private fun processedCustomPayloadKey(sessionId: String): String = "processed_custom_payload:$sessionId"

    private suspend fun requirePairedDevice(deviceId: String): PairedDevice {
        return store.getPairedDevice(deviceId) ?: error("Device is not paired")
    }

    private fun validatePairingKeys(device: PairedDevice) {
        crypto.validateP256PublicKey(device.signingPublicKeyB64)
        crypto.validateP256PublicKey(device.encryptionPublicKeyB64)
    }

    private fun normalizeFingerprint(value: String): String {
        return value.trim().replace("-", ":").replace(" ", ":")
    }

    private suspend fun appendAuditLog(
        eventType: String,
        subjectUserId: String?,
        subjectDeviceId: String?,
        sessionId: String?,
        result: String,
        metadata: Map<String, String> = emptyMap()
    ) {
        runCatching {
            val previous = store.getAuditLogEntries().maxByOrNull { it.sequence }
            val sequence = (previous?.sequence ?: 0L) + 1L
            val issuedAt = System.currentTimeMillis()
            val previousHash = previous?.entryHashB64
            val material = auditMaterial(
                sequence = sequence,
                eventType = eventType,
                subjectUserId = subjectUserId,
                subjectDeviceId = subjectDeviceId,
                sessionId = sessionId,
                result = result,
                issuedAtEpochMs = issuedAt,
                metadata = metadata,
                previousHashB64 = previousHash
            )
            val hash = sha256B64(material)
            val signature = crypto.sign(SIGNING_ALIAS, material)
            store.appendAuditLogEntry(
                AuditLogEntry(
                    sequence = sequence,
                    eventType = eventType,
                    subjectUserId = subjectUserId,
                    subjectDeviceId = subjectDeviceId,
                    sessionId = sessionId,
                    result = result,
                    issuedAtEpochMs = issuedAt,
                    metadata = metadata,
                    previousHashB64 = previousHash,
                    entryHashB64 = hash,
                    signatureB64 = signature
                )
            )
        }
    }

    private fun auditMaterial(
        sequence: Long,
        eventType: String,
        subjectUserId: String?,
        subjectDeviceId: String?,
        sessionId: String?,
        result: String,
        issuedAtEpochMs: Long,
        metadata: Map<String, String>,
        previousHashB64: String?
    ): String {
        val metadataText = metadata.toSortedMap().entries.joinToString("&") { "${it.key}=${it.value}" }
        return listOf(
            sequence.toString(),
            eventType,
            subjectUserId.orEmpty(),
            subjectDeviceId.orEmpty(),
            sessionId.orEmpty(),
            result,
            issuedAtEpochMs.toString(),
            metadataText,
            previousHashB64.orEmpty()
        ).joinToString("|")
    }

    private fun sha256B64(value: String): String {
        val bytes = MessageDigest.getInstance("SHA-256")
            .digest(value.toByteArray(StandardCharsets.UTF_8))
        return Base64.encodeToString(bytes, Base64.NO_WRAP)
    }

    private fun collectTrustRecency(
        sessions: List<SessionRecord>,
        requestEpochMs: Long,
        requesterUserId: String,
        targetUserId: String,
        fallbackTrustedEpochMs: Long?
    ): TrustRecencySignals {
        val lastTrustedRequest = sessions
            .filter {
                it.requesterUserId == requesterUserId &&
                    it.targetUserId == targetUserId &&
                    TRUSTED_DECISIONS.contains(it.lastDecision)
            }
            .maxOfOrNull { it.issuedAtEpochMs }
            ?: fallbackTrustedEpochMs

        if (lastTrustedRequest == null) {
            return TrustRecencySignals(
                lastTrustedRequestEpochMs = null,
                monthsSinceLastTrustedRequest = null,
                rawScore = 0,
                notes = listOf("No prior trusted request")
            )
        }

        val elapsedMs = (requestEpochMs - lastTrustedRequest).coerceAtLeast(0L)
        val monthsSinceTrustedRequest = (elapsedMs / TRUST_RECENCY_MONTH_MS).toInt().coerceAtMost(10)
        val rawScore = (10 - monthsSinceTrustedRequest).coerceIn(0, 10)
        return TrustRecencySignals(
            lastTrustedRequestEpochMs = lastTrustedRequest,
            monthsSinceLastTrustedRequest = monthsSinceTrustedRequest,
            rawScore = rawScore,
            notes = if (rawScore == 0) listOf("Last trusted request is older than trust recency cutoff") else emptyList()
        )
    }
}
