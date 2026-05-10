package com.example.ztaloc.device

import android.os.Build
import java.io.File

object RootIntegrityChecks {
    fun rootOrJailbreakSuspected(): Boolean {
        return hasTestKeys() || hasKnownRootFiles() || hasSuspiciousBuildTags()
    }

    fun reasons(): List<String> {
        val reasons = mutableListOf<String>()
        if (hasTestKeys()) reasons += "Build signed with test keys"
        if (hasKnownRootFiles()) reasons += "Root indicators detected"
        if (hasSuspiciousBuildTags()) reasons += "Suspicious build tags detected"
        return reasons
    }

    fun hasTestKeys(buildTags: String? = Build.TAGS): Boolean {
        return buildTags?.contains("test-keys", ignoreCase = true) == true
    }

    fun hasSuspiciousBuildTags(
        buildType: String = Build.TYPE,
        buildFingerprint: String = Build.FINGERPRINT
    ): Boolean {
        return buildType.equals("eng", ignoreCase = true) ||
            buildType.equals("userdebug", ignoreCase = true) ||
            buildFingerprint.contains("generic", ignoreCase = true) ||
            buildFingerprint.contains("unknown", ignoreCase = true)
    }

    private fun hasKnownRootFiles(): Boolean {
        return ROOT_PATHS.any { File(it).exists() }
    }

    private val ROOT_PATHS = listOf(
        "/system/app/Superuser.apk",
        "/sbin/su",
        "/system/bin/su",
        "/system/xbin/su",
        "/data/local/xbin/su",
        "/data/local/bin/su",
        "/system/sd/xbin/su",
        "/system/bin/failsafe/su",
        "/data/local/su",
        "/system/bin/magisk",
        "/system/xbin/magisk"
    )
}
