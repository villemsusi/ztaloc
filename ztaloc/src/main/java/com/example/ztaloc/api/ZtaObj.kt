package com.example.ztaloc.api

import android.app.Activity
import android.content.Context
import com.example.ztaloc.core.DefaultZtaLocationClient
import com.example.ztaloc.core.ZtaConfig

object ZtaObj {
    @Volatile
    private var client: ZtaLocationClient? = null

    fun initialize(context: Context, config: ZtaConfig = ZtaConfig()) {
        if (client == null) {
            synchronized(this) {
                if (client == null) {
                    client = DefaultZtaLocationClient(context.applicationContext, config)
                }
            }
        }
    }

    fun isInitialized(): Boolean = client != null

    private fun requireClient(): ZtaLocationClient {
        return requireNotNull(client) {
            "LocSafeZta is not initialized. Call LocSafeZta.initialize(context) first."
        }
    }

    suspend fun setupUser(userId: String, displayName: String? = null): Result<SetupResult> =
        requireClient().setupUser(userId, displayName)

    suspend fun getDeviceRegistrationInfo(): Result<DeviceRegistrationInfo> =
        requireClient().getDeviceRegistrationInfo()

    suspend fun getKeyLifecycleStatus(): Result<KeyLifecycleStatus> =
        requireClient().getKeyLifecycleStatus()

    suspend fun rotateLocalKeys(reason: String? = null): Result<KeyRotationResult> =
        requireClient().rotateLocalKeys(reason)

    suspend fun clearLocalKeyMaterial(): Result<Unit> =
        requireClient().clearLocalKeyMaterial()

    suspend fun upsertPairedDevice(device: PairedDevice, expectedPairingFingerprint: String): Result<Unit> =
        requireClient().upsertPairedDevice(device, expectedPairingFingerprint)

    suspend fun pairingFingerprint(device: PairedDevice): Result<String> =
        requireClient().pairingFingerprint(device)

    suspend fun removePairedDevice(deviceId: String): Result<Unit> =
        requireClient().removePairedDevice(deviceId)

    suspend fun listPairedDevices(): Result<List<PairedDevice>> =
        requireClient().listPairedDevices()

    suspend fun upsertSemanticLocationLabel(
        label: String,
        latitude: Double,
        longitude: Double,
        radiusMeters: Double? = null
    ): Result<Unit> =
        requireClient().upsertSemanticLocationLabel(label, latitude, longitude, radiusMeters)

    suspend fun removeSemanticLocationLabel(label: String): Result<Unit> =
        requireClient().removeSemanticLocationLabel(label)

    suspend fun listSemanticLocationLabels(): Result<List<SemanticLocationLabel>> =
        requireClient().listSemanticLocationLabels()

    suspend fun listSecureAuditLog(): Result<List<SecureAuditLogEntry>> =
        requireClient().listSecureAuditLog()

    suspend fun createLocationRequest(target: PairedDevice, activity: Activity): Result<OutgoingRequest> =
        requireClient().createLocationRequest(target, activity)

    suspend fun processIncomingRequest(requestPayload: String): Result<OutgoingResponse> =
        requireClient().processIncomingRequest(requestPayload)

    suspend fun processIncomingResponse(responsePayload: String): Result<LocationAccessResult> =
        requireClient().processIncomingResponse(responsePayload)

    suspend fun encryptPayload(target: PairedDevice, plaintext: String): Result<String> =
        requireClient().encryptPayload(target, plaintext)

    suspend fun decryptPayload(encryptedPayload: String): Result<String> =
        requireClient().decryptPayload(encryptedPayload)
}
