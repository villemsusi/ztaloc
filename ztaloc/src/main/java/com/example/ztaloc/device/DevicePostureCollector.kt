package com.example.ztaloc.device

import android.app.KeyguardManager
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.security.keystore.KeyInfo
import java.security.KeyFactory
import java.security.KeyStore
import java.security.MessageDigest

class DevicePostureCollector(
    private val context: Context,
    private val signingAlias: String = "zta_signing",
    private val expectedPackageName: String? = null,
    private val expectedApplicationChecksumSha256: String? = null
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
        val actualApplicationChecksum = applicationSigningCertificateChecksum()
        val packageMatches = expectedPackageName?.equals(context.packageName) ?: true
        if (!packageMatches) rationale += "Application package name mismatch"
        val checksumMatches = expectedApplicationChecksumSha256?.let { expected ->
            normalizeChecksum(expected) == normalizeChecksum(actualApplicationChecksum)
        } ?: true
        if (expectedApplicationChecksumSha256 == null) {
            rationale += "Application checksum validation not configured"
        } else if (!checksumMatches) {
            rationale += "Application checksum mismatch"
        }
        return DevicePosture(
            isRegistered = isRegistered,
            passesIntegrity = !rootDetected,
            osVersionRecentEnough = osRecent,
            secureLockEnabled = secureLock,
            hardwareBackedKeysAvailable = hardwareBackedKeys,
            applicationChecksumMatches = packageMatches && checksumMatches,
            applicationChecksumSha256 = actualApplicationChecksum,
            expectedApplicationChecksumSha256 = expectedApplicationChecksumSha256,
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

    @Suppress("DEPRECATION")
    private fun applicationSigningCertificateChecksum(): String? {
        return runCatching {
            val packageInfo = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                context.packageManager.getPackageInfo(context.packageName, PackageManager.GET_SIGNING_CERTIFICATES)
            } else {
                context.packageManager.getPackageInfo(context.packageName, PackageManager.GET_SIGNATURES)
            }
            val signerBytes = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                packageInfo.signingInfo?.apkContentsSigners?.firstOrNull()?.toByteArray()
            } else {
                packageInfo.signatures?.firstOrNull()?.toByteArray()
            } ?: return null
            MessageDigest.getInstance("SHA-256")
                .digest(signerBytes)
                .joinToString(":") { "%02X".format(it) }
        }.getOrNull()
    }

    private fun normalizeChecksum(value: String?): String? {
        return value?.trim()?.replace(":", "")?.replace("-", "")?.replace(" ", "")?.uppercase()
    }
}
