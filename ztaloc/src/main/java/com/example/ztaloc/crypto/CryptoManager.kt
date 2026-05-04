package com.example.ztaloc.crypto

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import java.nio.charset.StandardCharsets
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.PublicKey
import java.security.Signature
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

class CryptoManager(private val context: Context) {
    private val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }

    fun ensureSigningKey(alias: String) {
        if (keyStore.containsAlias(alias)) return
        val generator =
            KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore")
        val spec = KeyGenParameterSpec.Builder(
            alias,
            KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
        )
            .setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA512)
            .build()
        generator.initialize(spec)
        generator.generateKeyPair()
    }

    fun getPublicKey(alias: String): String {
        val cert = keyStore.getCertificate(alias)
        return Base64.encodeToString(cert.publicKey.encoded, Base64.NO_WRAP)
    }

    fun sign(alias: String, payload: String): String {
        val entry = keyStore.getEntry(alias, null) as KeyStore.PrivateKeyEntry
        val signature = Signature.getInstance("SHA256withECDSA")
        signature.initSign(entry.privateKey)
        signature.update(payload.toByteArray(StandardCharsets.UTF_8))
        return Base64.encodeToString(signature.sign(), Base64.NO_WRAP)
    }

    fun verify(publicKey: PublicKey, payload: String, signatureB64: String): Boolean {
        val sig = Signature.getInstance("SHA256withECDSA")
        sig.initVerify(publicKey)
        sig.update(payload.toByteArray(StandardCharsets.UTF_8))
        return sig.verify(Base64.decode(signatureB64, Base64.NO_WRAP))
    }

    fun ensureAesKey(alias: String) {
        if (keyStore.containsAlias(alias)) return
        val keyGenerator =
            KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        val spec = KeyGenParameterSpec.Builder(
            alias,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setRandomizedEncryptionRequired(true)
            .build()
        keyGenerator.init(spec)
        keyGenerator.generateKey()
    }

    fun encrypt(alias: String, plaintext: String): EncryptedBlob {
        val secret = keyStore.getKey(alias, null) as SecretKey
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, secret)
        val iv = cipher.iv
        val cipherBytes = cipher.doFinal(plaintext.toByteArray(StandardCharsets.UTF_8))
        return EncryptedBlob(
            ciphertextB64 = Base64.encodeToString(cipherBytes, Base64.NO_WRAP),
            ivB64 = Base64.encodeToString(iv, Base64.NO_WRAP)
        )
    }

    fun decrypt(alias: String, blob: EncryptedBlob): String {
        val secret = keyStore.getKey(alias, null) as SecretKey
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        val iv = Base64.decode(blob.ivB64, Base64.NO_WRAP)
        val spec = GCMParameterSpec(128, iv)
        cipher.init(Cipher.DECRYPT_MODE, secret, spec)
        val bytes = cipher.doFinal(Base64.decode(blob.ciphertextB64, Base64.NO_WRAP))
        return String(bytes, StandardCharsets.UTF_8)
    }
}

data class EncryptedBlob(
    val ciphertextB64: String,
    val ivB64: String
)