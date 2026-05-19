package com.example.ztaloc.device

import android.content.Context
import android.util.Base64
import com.google.android.play.core.integrity.IntegrityManagerFactory
import com.google.android.play.core.integrity.IntegrityTokenRequest
import kotlinx.coroutines.suspendCancellableCoroutine
import java.security.MessageDigest
import java.security.SecureRandom
import kotlin.coroutines.resume

internal class PlayIntegrityChecker(
    private val context: Context
) {
    private val random = SecureRandom()

    suspend fun requestIntegrityToken(): Boolean {
        val nonce = nonce()
        val request = IntegrityTokenRequest.builder()
            .setNonce(nonce)
            .build()
        return suspendCancellableCoroutine { continuation ->
            val task = IntegrityManagerFactory.create(context).requestIntegrityToken(request)
            task.addOnSuccessListener { response ->
                if (continuation.isActive) {
                    continuation.resume(response.token().isNotBlank())
                }
            }
            task.addOnFailureListener {
                if (continuation.isActive) {
                    continuation.resume(false)
                }
            }
        }
    }

    private fun nonce(): String {
        val bytes = ByteArray(NONCE_BYTES).also { random.nextBytes(it) }
        val digest = MessageDigest.getInstance("SHA-256").digest(bytes)
        return Base64.encodeToString(digest, Base64.NO_WRAP or Base64.URL_SAFE)
    }

    private companion object {
        private const val NONCE_BYTES = 32
    }
}
