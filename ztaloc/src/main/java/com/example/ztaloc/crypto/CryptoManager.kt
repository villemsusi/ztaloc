package com.example.ztaloc.crypto

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import kotlinx.serialization.Serializable
import java.nio.charset.StandardCharsets
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PublicKey
import java.security.Signature
import java.security.spec.X509EncodedKeySpec
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

class TransportCrypto {
    private val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }

    fun ensureSigningKey(alias: String) {
        if (keyStore.containsAlias(alias)) return
        val generator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore")
        val spec = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY)
            .setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA512)
            .build()
        generator.initialize(spec)
        generator.generateKeyPair()
    }

    fun ensureEncryptionKey(alias: String) {
        if (keyStore.containsAlias(alias)) return
        val generator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA, "AndroidKeyStore")
        val spec = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_DECRYPT or KeyProperties.PURPOSE_ENCRYPT)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_OAEP)
            .setKeySize(2048)
            .build()
        generator.initialize(spec)
        generator.generateKeyPair()
    }
    fun exportPublicKey(alias: String): String {
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

    fun verify(publicKeyB64: String, payload: String, signatureB64: String): Boolean {
        val publicKey = decodePublicKey(publicKeyB64, "EC")
        val signature = Signature.getInstance("SHA256withECDSA")
        signature.initVerify(publicKey)
        signature.update(payload.toByteArray(StandardCharsets.UTF_8))
        return signature.verify(Base64.decode(signatureB64, Base64.NO_WRAP))
    }

    fun hybridEncrypt(recipientEncryptionPublicKeyB64: String, plaintext: String, senderDeviceId: String, recipientDeviceId: String): HybridEncryptedEnvelope {
        val aesKey = KeyGenerator.getInstance("AES").apply { init(256) }.generateKey()
        val aesCipher = Cipher.getInstance("AES/GCM/NoPadding")
        aesCipher.init(Cipher.ENCRYPT_MODE, aesKey)
        val iv = aesCipher.iv
        val cipherBytes = aesCipher.doFinal(plaintext.toByteArray(StandardCharsets.UTF_8))

        val recipientPublicKey = decodePublicKey(recipientEncryptionPublicKeyB64, "RSA")
        val rsaCipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding")
        rsaCipher.init(Cipher.ENCRYPT_MODE, recipientPublicKey)
        val wrappedKey = rsaCipher.doFinal(aesKey.encoded)

        return HybridEncryptedEnvelope(
            ciphertextB64 = Base64.encodeToString(cipherBytes, Base64.NO_WRAP),
            ivB64 = Base64.encodeToString(iv, Base64.NO_WRAP),
            wrappedAesKeyB64 = Base64.encodeToString(wrappedKey, Base64.NO_WRAP),
            senderDeviceId = senderDeviceId,
            recipientDeviceId = recipientDeviceId
        )
    }
    fun hybridDecrypt(recipientEncryptionAlias: String, envelope: HybridEncryptedEnvelope): String {
        val entry = keyStore.getEntry(recipientEncryptionAlias, null) as KeyStore.PrivateKeyEntry
        val rsaCipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding")
        rsaCipher.init(Cipher.DECRYPT_MODE, entry.privateKey)
        val aesRaw = rsaCipher.doFinal(Base64.decode(envelope.wrappedAesKeyB64, Base64.NO_WRAP))
        val aesKey = SecretKeySpec(aesRaw, "AES")

        val aesCipher = Cipher.getInstance("AES/GCM/NoPadding")
        aesCipher.init(
            Cipher.DECRYPT_MODE,
            aesKey,
            GCMParameterSpec(128, Base64.decode(envelope.ivB64, Base64.NO_WRAP))
        )
        val plain = aesCipher.doFinal(Base64.decode(envelope.ciphertextB64, Base64.NO_WRAP))
        return String(plain, StandardCharsets.UTF_8)
    }

    private fun decodePublicKey(publicKeyB64: String, algorithm: String): PublicKey {
        val bytes = Base64.decode(publicKeyB64, Base64.NO_WRAP)
        return KeyFactory.getInstance(algorithm).generatePublic(X509EncodedKeySpec(bytes))
    }
}

@Serializable
data class HybridEncryptedEnvelope(
    val ciphertextB64: String,
    val ivB64: String,
    val wrappedAesKeyB64: String,
    val senderDeviceId: String,
    val recipientDeviceId: String
)