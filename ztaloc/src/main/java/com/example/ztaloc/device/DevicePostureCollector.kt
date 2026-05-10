package com.example.ztaloc.device

import android.app.KeyguardManager
import android.content.Context
import android.os.Build
import android.security.keystore.KeyInfo
import java.security.KeyFactory
import java.security.KeyStore

class DevicePostureCollector(
    private val context: Context,
    private val signingAlias: String = "zta_signing"
) {
    fun collect(isRegistered: Boolean): DevicePosture {
        val rationale = mutableListOf<String>()
        val rootDetected = RootIntegrityChecks.rootOrJailbreakSuspected()
        rationale += RootIntegrityChecks.reasons()
        val keyguardManager = context.getSystemService(Context.KEYGUARD_SERVICE) as KeyguardManager
        val secureLock = keyguardManager.isDeviceSecure.also { if (!it) rationale += "Secure lock screen disabled" }
        val osRecent = Build.VERSION.SDK_INT >= Build.VERSION_CODES.R
        if (!osRecent) rationale += "OS version considered old"
        val hardwareBackedKeys = hasHardwareBackedSigningKey()
        if (!hardwareBackedKeys) rationale += "Signing key is not hardware-backed"
        return DevicePosture(
            isRegistered = isRegistered,
            passesIntegrity = !rootDetected,
            osVersionRecentEnough = osRecent,
            secureLockEnabled = secureLock,
            hardwareBackedKeysAvailable = hardwareBackedKeys,
            rootOrJailbreakSuspected = rootDetected,
            rationale = rationale
        )
    }

    @Suppress("DEPRECATION")
    private fun hasHardwareBackedSigningKey(): Boolean {
        return runCatching {
            val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
            val privateKey = keyStore.getKey(signingAlias, null) ?: return false
            val keyFactory = KeyFactory.getInstance(privateKey.algorithm, "AndroidKeyStore")
            val keyInfo = keyFactory.getKeySpec(privateKey, KeyInfo::class.java)
            keyInfo.isInsideSecureHardware
        }.getOrDefault(false)
    }
}
