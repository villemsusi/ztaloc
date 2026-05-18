package com.example.ztaloc.api

import android.app.Activity

interface ZtaLocationClient {
    suspend fun setupUser(userId: String, displayName: String? = null): Result<SetupResult>
    suspend fun getDeviceRegistrationInfo(): Result<DeviceRegistrationInfo>
    suspend fun upsertPairedDevice(device: PairedDevice, expectedPairingFingerprint: String): Result<Unit>
    suspend fun pairingFingerprint(device: PairedDevice): Result<String>
    suspend fun removePairedDevice(deviceId: String): Result<Unit>
    suspend fun listPairedDevices(): Result<List<PairedDevice>>
    suspend fun upsertSemanticLocationLabel(
        label: String,
        latitude: Double,
        longitude: Double,
        radiusMeters: Double? = null
    ): Result<Unit>
    suspend fun removeSemanticLocationLabel(label: String): Result<Unit>
    suspend fun listSemanticLocationLabels(): Result<List<SemanticLocationLabel>>

    suspend fun createLocationRequest(target: PairedDevice, activity: Activity): Result<OutgoingRequest>
    suspend fun processIncomingRequest(requestPayload: String): Result<OutgoingResponse>
    suspend fun processIncomingResponse(responsePayload: String): Result<LocationAccessResult>
    suspend fun encryptPayload(target: PairedDevice, plaintext: String): Result<String>
    suspend fun decryptPayload(encryptedPayload: String): Result<String>
}
