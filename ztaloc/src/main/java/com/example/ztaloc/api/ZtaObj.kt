package com.example.ztaloc.api

import android.content.Context
import com.example.ztaloc.core.DefaultZtaLocationClient

object ZtaObj {
    @Volatile
    private var client: ZtaLocationClient? = null

    fun initialize(context: Context) {
        if (client == null) {
            synchronized(this) {
                if (client == null) {
                    client = DefaultZtaLocationClient(context.applicationContext)
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

    suspend fun upsertPairedDevice(device: PairedDevice): Result<Unit> =
        requireClient().upsertPairedDevice(device)

    suspend fun removePairedDevice(deviceId: String): Result<Unit> =
        requireClient().removePairedDevice(deviceId)

    suspend fun listPairedDevices(): Result<List<PairedDevice>> =
        requireClient().listPairedDevices()

    suspend fun upsertSemanticLocationLabel(label: String, latitude: Double, longitude: Double): Result<Unit> =
        requireClient().upsertSemanticLocationLabel(label, latitude, longitude)

    suspend fun removeSemanticLocationLabel(label: String): Result<Unit> =
        requireClient().removeSemanticLocationLabel(label)

    suspend fun listSemanticLocationLabels(): Result<List<SemanticLocationLabel>> =
        requireClient().listSemanticLocationLabels()

    suspend fun createLocationRequest(target: PairedDevice): Result<OutgoingRequest> =
        requireClient().createLocationRequest(target)

    suspend fun processIncomingRequest(requestPayload: String): Result<OutgoingResponse> =
        requireClient().processIncomingRequest(requestPayload)

    suspend fun processIncomingResponse(responsePayload: String): Result<LocationAccessResult> =
        requireClient().processIncomingResponse(responsePayload)

    suspend fun reevaluateSession(sessionId: String): Result<LocationAccessResult> =
        requireClient().reevaluateSession(sessionId)
}
