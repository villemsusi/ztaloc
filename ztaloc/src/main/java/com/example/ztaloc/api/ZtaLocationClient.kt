package com.example.ztaloc.api

import android.content.Context
import com.example.ztaloc.core.DefaultZtaLocationClient
import com.example.ztaloc.core.ZtaConfig

interface ZtaLocationClient {
    suspend fun initializeUser(userId: String, displayName: String? = null): Result<Unit>
    suspend fun registerCurrentDevice(): Result<DeviceRegistrationResult>
    suspend fun requestLocation(targetUserId: String): Result<LocationAccessResult>
    suspend fun respondToLocationRequest(requestEnvelopeJson: String): Result<String>
    suspend fun reevaluateSession(sessionId: String): Result<LocationAccessResult>
}

object ZtaLocation {
    fun create(context: Context, config: ZtaConfig): ZtaLocationClient {
        return DefaultZtaLocationClient(context.applicationContext, config)
    }
}