package com.example.ztaloc.data

import android.content.Context
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import kotlinx.serialization.encodeToString
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.json.Json
import java.util.UUID

class LocalStore(context: Context) {
    private val json = Json { ignoreUnknownKeys = true }
    private val masterKey = MasterKey.Builder(context)
        .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
        .build()
    private val prefs = EncryptedSharedPreferences.create(
        context,
        "zta_store",
        masterKey,
        EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
        EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
    )

    fun saveUser(user: LocalUser) {
        prefs.edit().putString("user", json.encodeToString(user)).apply()
    }

    fun getUser(): LocalUser? = prefs.getString("user", null)?.let { json.decodeFromString<LocalUser>(it) }

    fun putSession(record: SessionRecord) {
        prefs.edit().putString("session:${record.sessionId}", json.encodeToString(record)).apply()
    }

    fun getSession(sessionId: String): SessionRecord? {
        return prefs.getString("session:$sessionId", null)?.let { json.decodeFromString<SessionRecord>(it) }
    }

    fun putString(key: String, value: String) {
        prefs.edit().putString(key, value).apply()
    }

    fun getString(key: String): String? = prefs.getString(key, null)

    fun remove(key: String) {
        prefs.edit().remove(key).apply()
    }

    fun newDeviceId(): String = UUID.randomUUID().toString()
}
