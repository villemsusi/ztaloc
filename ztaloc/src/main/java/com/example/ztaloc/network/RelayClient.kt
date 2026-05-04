package com.example.ztaloc.network

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.encodeToString
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.json.Json
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody

class RelayClient(private val okHttpClient: OkHttpClient, private val baseUrl: String) {
    private val json = Json { ignoreUnknownKeys = true }

    suspend fun registerDevice(payload: DeviceRegistrationPayload): Result<DeviceRegistrationResponse> = withContext(Dispatchers.IO) {
        runCatching {
            val req = Request.Builder()
                .url("$baseUrl/devices/register")
                .post(json.encodeToString(payload).toRequestBody("application/json".toMediaType()))
                .build()
            okHttpClient.newCall(req).execute().use {
                if (!it.isSuccessful) error("Relay device registration failed: ${it.code}")
                val body = requireNotNull(it.body).string()
                json.decodeFromString<DeviceRegistrationResponse>(body)
            }
        }
    }

    suspend fun sendRequest(envelope: RequestEnvelope): Result<Unit> = withContext(Dispatchers.IO) {
        runCatching {
            val req = Request.Builder()
                .url("$baseUrl/requests")
                .post(json.encodeToString(envelope).toRequestBody("application/json".toMediaType()))
                .build()
            okHttpClient.newCall(req).execute().use {
                if (!it.isSuccessful) error("Relay request failed: ${it.code}")
            }
        }
    }

    suspend fun sendResponse(envelope: ResponseEnvelope): Result<Unit> = withContext(Dispatchers.IO) {
        runCatching {
            val req = Request.Builder()
                .url("$baseUrl/responses")
                .post(json.encodeToString(envelope).toRequestBody("application/json".toMediaType()))
                .build()
            okHttpClient.newCall(req).execute().use {
                if (!it.isSuccessful) error("Relay response failed: ${it.code}")
            }
        }
    }
}