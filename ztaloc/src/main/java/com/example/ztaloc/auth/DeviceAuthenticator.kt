package com.example.ztaloc.auth

import android.app.Activity
import android.hardware.biometrics.BiometricManager
import android.hardware.biometrics.BiometricPrompt
import android.os.CancellationSignal
import com.example.ztaloc.api.LocalAuthenticationResult
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlin.coroutines.resume

class DeviceAuthenticator {
    suspend fun authenticateForLocationRequest(activity: Activity): LocalAuthenticationResult {
        return authenticate(
            activity = activity,
            title = "Authenticate location request",
            subtitle = "Confirm with your device credential to continue"
        )
    }

    private suspend fun authenticate(
        activity: Activity,
        title: String,
        subtitle: String
    ): LocalAuthenticationResult {
        val authenticators =
            BiometricManager.Authenticators.BIOMETRIC_STRONG or
                BiometricManager.Authenticators.DEVICE_CREDENTIAL

        val biometricManager = activity.getSystemService(BiometricManager::class.java)
        val canAuthenticate = biometricManager.canAuthenticate(authenticators)
        if (canAuthenticate != BiometricManager.BIOMETRIC_SUCCESS) {
            return LocalAuthenticationResult(
                authenticated = false,
                multiFactorSatisfied = false,
                reason = "Device authentication is not available"
            )
        }

        return suspendCancellableCoroutine { continuation ->
            val cancellationSignal = CancellationSignal()
            continuation.invokeOnCancellation { cancellationSignal.cancel() }

            val prompt = BiometricPrompt.Builder(activity)
                .setTitle(title)
                .setSubtitle(subtitle)
                .setAllowedAuthenticators(authenticators)
                .build()

            prompt.authenticate(
                cancellationSignal,
                activity.mainExecutor,
                object : BiometricPrompt.AuthenticationCallback() {
                    override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                        if (continuation.isActive) {
                            continuation.resume(
                                LocalAuthenticationResult(
                                    authenticated = true,
                                    multiFactorSatisfied = true,
                                    reason = "Device credential verified"
                                )
                            )
                        }
                    }

                    override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                        if (continuation.isActive) {
                            continuation.resume(
                                LocalAuthenticationResult(
                                    authenticated = false,
                                    multiFactorSatisfied = false,
                                    reason = errString.toString()
                                )
                            )
                        }
                    }

                    override fun onAuthenticationFailed() {
                        // The platform prompt may allow another biometric attempt after this callback.
                        // Only terminal errors or cancellation should complete the authentication flow.
                    }
                }
            )
        }
    }
}
