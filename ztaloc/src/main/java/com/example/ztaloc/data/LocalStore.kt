package com.example.ztaloc.data

import android.content.Context
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import com.example.ztaloc.api.PairedDevice
import com.example.ztaloc.api.SemanticLocationLabel
import kotlinx.coroutines.flow.first
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import java.util.UUID
private val Context.ztaDataStore by preferencesDataStore(name = "zta_store")

class LocalStore(
    private val context: Context
) {
    private val json = Json { ignoreUnknownKeys = true; encodeDefaults = true }
    private val storeCodec = EncryptedStoreCodec()

    suspend fun saveUser(user: LocalUser) {
        context.ztaDataStore.edit { prefs -> prefs[USER_KEY] = protect(json.encodeToString(user)) }
    }

    suspend fun getUser(): LocalUser? {
        val raw = context.ztaDataStore.data.first()[USER_KEY] ?: return null
        return runCatching { json.decodeFromString<LocalUser>(unprotect(raw)) }.getOrNull()
    }

    suspend fun putSession(record: SessionRecord) {
        context.ztaDataStore.edit { prefs -> prefs[sessionKey(record.sessionId)] = protect(json.encodeToString(record)) }
    }

    suspend fun getSession(sessionId: String): SessionRecord? {
        val raw = context.ztaDataStore.data.first()[sessionKey(sessionId)] ?: return null
        return runCatching { json.decodeFromString<SessionRecord>(unprotect(raw)) }.getOrNull()
    }

    suspend fun getSessions(): List<SessionRecord> {
        return context.ztaDataStore.data.first().asMap()
            .filterKeys { it.name.startsWith(SESSION_PREFIX) }
            .values
            .mapNotNull { raw -> runCatching { json.decodeFromString<SessionRecord>(unprotect(raw.toString())) }.getOrNull() }
    }

    suspend fun getAuditLogEntries(): List<AuditLogEntry> {
        val raw = context.ztaDataStore.data.first()[AUDIT_LOG_KEY] ?: return emptyList()
        return runCatching { json.decodeFromString<AuditLogEntryList>(unprotect(raw)).entries }.getOrDefault(emptyList())
    }

    suspend fun appendAuditLogEntry(entry: AuditLogEntry, maxEntries: Int = MAX_AUDIT_LOG_ENTRIES) {
        val updated = (getAuditLogEntries() + entry).takeLast(maxEntries)
        context.ztaDataStore.edit { prefs ->
            prefs[AUDIT_LOG_KEY] = protect(json.encodeToString(AuditLogEntryList(updated)))
        }
    }

    suspend fun putString(key: String, value: String) {
        context.ztaDataStore.edit { prefs -> prefs[stringPreferencesKey(key)] = protect(value) }
    }

    suspend fun getString(key: String): String? =
        context.ztaDataStore.data.first()[stringPreferencesKey(key)]?.let { unprotect(it) }

    suspend fun remove(key: String) {
        context.ztaDataStore.edit { prefs -> prefs.remove(stringPreferencesKey(key)) }
    }

    suspend fun getPairedDevices(): List<PairedDevice> {
        val raw = context.ztaDataStore.data.first()[PAIRED_DEVICES_KEY] ?: return emptyList()
        return runCatching { json.decodeFromString<PairedDeviceList>(unprotect(raw)).devices }.getOrDefault(emptyList())
    }

    suspend fun upsertPairedDevice(device: PairedDevice) {
        val updated = getPairedDevices().filterNot { it.deviceId == device.deviceId } + device
        context.ztaDataStore.edit { prefs ->
            prefs[PAIRED_DEVICES_KEY] = protect(json.encodeToString(PairedDeviceList(updated)))
        }
    }

    suspend fun removePairedDevice(deviceId: String) {
        val updated = getPairedDevices().filterNot { it.deviceId == deviceId }
        context.ztaDataStore.edit { prefs ->
            if (updated.isEmpty()) {
                prefs.remove(PAIRED_DEVICES_KEY)
            } else {
                prefs[PAIRED_DEVICES_KEY] = protect(json.encodeToString(PairedDeviceList(updated)))
            }
        }
    }

    suspend fun getPairedDevice(deviceId: String): PairedDevice? = getPairedDevices().firstOrNull { it.deviceId == deviceId }

    suspend fun getSemanticLocationLabels(): List<SemanticLocationLabel> {
        val raw = context.ztaDataStore.data.first()[SEMANTIC_LABELS_KEY] ?: return emptyList()
        return runCatching { json.decodeFromString<SemanticLocationLabelList>(unprotect(raw)).labels }.getOrDefault(emptyList())
    }

    suspend fun upsertSemanticLocationLabel(label: SemanticLocationLabel) {
        val normalized = label.copy(
            label = label.label.trim(),
            radiusMeters = label.radiusMeters
        )
        require(normalized.label.isNotBlank()) { "Semantic location label must not be blank" }
        require(normalized.latitude in -90.0..90.0) { "Semantic location latitude must be between -90 and 90" }
        require(normalized.longitude in -180.0..180.0) { "Semantic location longitude must be between -180 and 180" }
        require(normalized.radiusMeters > 0.0) { "Semantic location radius must be greater than 0" }

        val updated = getSemanticLocationLabels()
            .filterNot { it.label.equals(normalized.label, ignoreCase = true) } + normalized
        context.ztaDataStore.edit { prefs ->
            prefs[SEMANTIC_LABELS_KEY] = protect(json.encodeToString(SemanticLocationLabelList(updated)))
        }
    }

    suspend fun removeSemanticLocationLabel(label: String) {
        val updated = getSemanticLocationLabels().filterNot { it.label.equals(label.trim(), ignoreCase = true) }
        context.ztaDataStore.edit { prefs ->
            if (updated.isEmpty()) {
                prefs.remove(SEMANTIC_LABELS_KEY)
            } else {
                prefs[SEMANTIC_LABELS_KEY] = protect(json.encodeToString(SemanticLocationLabelList(updated)))
            }
        }
    }

    fun newDeviceId(): String = UUID.randomUUID().toString()

    private fun sessionKey(sessionId: String): Preferences.Key<String> = stringPreferencesKey("$SESSION_PREFIX$sessionId")

    private fun protect(value: String): String = storeCodec.encode(value)

    private fun unprotect(value: String): String = storeCodec.decode(value)

    companion object {
        private const val SESSION_PREFIX = "session:"
        private val USER_KEY = stringPreferencesKey("user")
        private val PAIRED_DEVICES_KEY = stringPreferencesKey("paired_devices")
        private val SEMANTIC_LABELS_KEY = stringPreferencesKey("semantic_location_labels")
        private val AUDIT_LOG_KEY = stringPreferencesKey("audit_log")
        private const val MAX_AUDIT_LOG_ENTRIES = 500
    }
}
