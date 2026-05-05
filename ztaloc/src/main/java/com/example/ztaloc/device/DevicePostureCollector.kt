package com.example.ztaloc.device

import android.app.KeyguardManager
import android.content.Context
import android.os.Build
import java.io.File

class DevicePostureCollector(private val context: Context) {
    fun collect(isRegistered: Boolean): DevicePosture {
        val rationale = mutableListOf<String>()
        val rootDetected = isRootDetected().also { if (it) rationale += "Root indicators detected" }
        val keyguardManager = context.getSystemService(Context.KEYGUARD_SERVICE) as KeyguardManager
        val secureLock = keyguardManager.isDeviceSecure.also { if (!it) rationale += "Secure lock screen disabled" }
        val osRecent = Build.VERSION.SDK_INT >= Build.VERSION_CODES.R
        if (!osRecent) rationale += "OS version considered old"
        return DevicePosture(
            isRegistered = isRegistered,
            passesIntegrity = !rootDetected,
            osVersionRecentEnough = osRecent,
            secureLockEnabled = secureLock,
            hardwareBackedKeysAvailable = true,
            rootOrJailbreakSuspected = rootDetected,
            rationale = rationale
        )
    }

    private fun isRootDetected(): Boolean {
        val paths = listOf(
            "/system/app/Superuser.apk",
            "/sbin/su",
            "/system/bin/su",
            "/system/xbin/su",
            "/data/local/xbin/su",
            "/data/local/bin/su",
            "/system/sd/xbin/su",
            "/system/bin/failsafe/su",
            "/data/local/su"
        )
        return paths.any { File(it).exists() }
    }
}