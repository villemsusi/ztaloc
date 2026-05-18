package com.example.ztaloc.crypto

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import android.util.Base64
import kotlinx.serialization.Serializable
import java.nio.charset.StandardCharsets
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.PublicKey
import java.security.SecureRandom
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.X509EncodedKeySpec
import javax.crypto.Cipher
import javax.crypto.KeyAgreement
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

class TransportCrypto {
    private val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
    private val secureRandom = SecureRandom()

    fun ensureSigningKey(alias: String) {
        if (keyStore.containsAlias(alias) && isEcP256Key(alias)) return
        if (keyStore.containsAlias(alias)) keyStore.deleteEntry(alias)
        val generator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore")
        val spec = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY)
            .setAlgorithmParameterSpec(ECGenParameterSpec(P256_CURVE))
            .setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA512)
            .build()
        generator.initialize(spec)
        generator.generateKeyPair()
    }

    fun ensureEncryptionKey(alias: String) {
        if (keyStore.containsAlias(alias) && encryptionKeySupportsEcdhP256(alias)) return
        if (keyStore.containsAlias(alias)) keyStore.deleteEntry(alias)
        val generator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore")
        val spec = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_AGREE_KEY)
            .setAlgorithmParameterSpec(ECGenParameterSpec(P256_CURVE))
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

    fun pairingFingerprint(signingPublicKeyB64: String, encryptionPublicKeyB64: String): String {
        val material = "zta-pairing-v1|$signingPublicKeyB64|$encryptionPublicKeyB64"
            .toByteArray(StandardCharsets.UTF_8)
        return MessageDigest.getInstance("SHA-256")
            .digest(material)
            .joinToString(":") { "%02X".format(it) }
    }

    fun validateP256PublicKey(publicKeyB64: String) {
        require(isEcP256PublicKey(decodePublicKey(publicKeyB64, "EC"))) {
            "Public key must be an EC P-256 key"
        }
    }

    fun hybridEncrypt(recipientEncryptionPublicKeyB64: String, plaintext: String, senderDeviceId: String, recipientDeviceId: String): HybridEncryptedEnvelope {
        val recipientPublicKey = decodePublicKey(recipientEncryptionPublicKeyB64, "EC")
        val ephemeralKeyPair = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC).run {
            initialize(ECGenParameterSpec(P256_CURVE), secureRandom)
            generateKeyPair()
        }
        val salt = randomBytes(HKDF_SALT_BYTES)
        val iv = randomBytes(GCM_IV_BYTES)
        val aesKey = deriveAesKey(
            sharedSecret = ecdh(ephemeralKeyPair.private, recipientPublicKey),
            salt = salt,
            senderDeviceId = senderDeviceId,
            recipientDeviceId = recipientDeviceId
        )

        val aesCipher = Cipher.getInstance("AES/GCM/NoPadding")
        aesCipher.init(Cipher.ENCRYPT_MODE, aesKey, GCMParameterSpec(GCM_TAG_BITS, iv))
        val cipherBytes = aesCipher.doFinal(plaintext.toByteArray(StandardCharsets.UTF_8))

        return HybridEncryptedEnvelope(
            algorithm = ENVELOPE_ALGORITHM,
            ephemeralPublicKeyB64 = Base64.encodeToString(ephemeralKeyPair.public.encoded, Base64.NO_WRAP),
            saltB64 = Base64.encodeToString(salt, Base64.NO_WRAP),
            ciphertextB64 = Base64.encodeToString(cipherBytes, Base64.NO_WRAP),
            ivB64 = Base64.encodeToString(iv, Base64.NO_WRAP),
            senderDeviceId = senderDeviceId,
            recipientDeviceId = recipientDeviceId
        )
    }

    fun hybridDecrypt(recipientEncryptionAlias: String, envelope: HybridEncryptedEnvelope): String {
        require(envelope.algorithm == ENVELOPE_ALGORITHM) {
            "Unsupported encrypted envelope algorithm: ${envelope.algorithm}"
        }
        val entry = keyStore.getEntry(recipientEncryptionAlias, null) as KeyStore.PrivateKeyEntry
        val ephemeralPublicKey = decodePublicKey(envelope.ephemeralPublicKeyB64, "EC")
        val aesKey = deriveAesKey(
            sharedSecret = ecdh(entry.privateKey, ephemeralPublicKey),
            salt = Base64.decode(envelope.saltB64, Base64.NO_WRAP),
            senderDeviceId = envelope.senderDeviceId,
            recipientDeviceId = envelope.recipientDeviceId
        )

        val aesCipher = Cipher.getInstance("AES/GCM/NoPadding")
        aesCipher.init(
            Cipher.DECRYPT_MODE,
            aesKey,
            GCMParameterSpec(GCM_TAG_BITS, Base64.decode(envelope.ivB64, Base64.NO_WRAP))
        )
        val plain = aesCipher.doFinal(Base64.decode(envelope.ciphertextB64, Base64.NO_WRAP))
        return String(plain, StandardCharsets.UTF_8)
    }

    private fun decodePublicKey(publicKeyB64: String, algorithm: String): PublicKey {
        val bytes = Base64.decode(publicKeyB64, Base64.NO_WRAP)
        return KeyFactory.getInstance(algorithm).generatePublic(X509EncodedKeySpec(bytes))
    }

    private fun encryptionKeySupportsEcdhP256(alias: String): Boolean = runCatching {
        val entry = keyStore.getEntry(alias, null) as KeyStore.PrivateKeyEntry
        if (!isEcP256PublicKey(entry.certificate.publicKey)) return@runCatching false
        val keyInfo = KeyFactory.getInstance(entry.privateKey.algorithm, "AndroidKeyStore")
            .getKeySpec(entry.privateKey, KeyInfo::class.java)
        keyInfo.purposes and KeyProperties.PURPOSE_AGREE_KEY != 0
    }.getOrDefault(false)

    private fun isEcP256Key(alias: String): Boolean = runCatching {
        val cert = keyStore.getCertificate(alias) ?: return@runCatching false
        isEcP256PublicKey(cert.publicKey)
    }.getOrDefault(false)

    private fun isEcP256PublicKey(publicKey: PublicKey): Boolean {
        val ecPublicKey = publicKey as? ECPublicKey ?: return false
        return ecPublicKey.params.curve.field.fieldSize == 256
    }

    private fun ecdh(privateKey: PrivateKey, publicKey: PublicKey): ByteArray {
        val agreement = KeyAgreement.getInstance("ECDH")
        agreement.init(privateKey)
        agreement.doPhase(publicKey, true)
        return agreement.generateSecret()
    }

    private fun deriveAesKey(
        sharedSecret: ByteArray,
        salt: ByteArray,
        senderDeviceId: String,
        recipientDeviceId: String
    ): SecretKeySpec {
        val info = "$ENVELOPE_ALGORITHM|$senderDeviceId|$recipientDeviceId"
            .toByteArray(StandardCharsets.UTF_8)
        return SecretKeySpec(hkdfSha256(sharedSecret, salt, info, AES_KEY_BYTES), "AES")
    }

    private fun hkdfSha256(inputKeyMaterial: ByteArray, salt: ByteArray, info: ByteArray, outputLength: Int): ByteArray {
        val prk = hmacSha256(salt, inputKeyMaterial)
        val output = ByteArray(outputLength)
        var previous = ByteArray(0)
        var generated = 0
        var counter = 1

        while (generated < outputLength) {
            val mac = Mac.getInstance(HMAC_SHA256)
            mac.init(SecretKeySpec(prk, HMAC_SHA256))
            mac.update(previous)
            mac.update(info)
            mac.update(counter.toByte())
            previous = mac.doFinal()

            val copyLength = minOf(previous.size, outputLength - generated)
            previous.copyInto(output, generated, 0, copyLength)
            generated += copyLength
            counter += 1
        }

        return output
    }

    private fun hmacSha256(key: ByteArray, data: ByteArray): ByteArray {
        val mac = Mac.getInstance(HMAC_SHA256)
        mac.init(SecretKeySpec(key, HMAC_SHA256))
        return mac.doFinal(data)
    }

    private fun randomBytes(size: Int): ByteArray {
        return ByteArray(size).also { secureRandom.nextBytes(it) }
    }

    private companion object {
        private const val P256_CURVE = "secp256r1"
        private const val HMAC_SHA256 = "HmacSHA256"
        private const val ENVELOPE_ALGORITHM = "P-256-ECDH-HKDF-SHA256-AES-256-GCM"
        private const val AES_KEY_BYTES = 32
        private const val GCM_IV_BYTES = 12
        private const val GCM_TAG_BITS = 128
        private const val HKDF_SALT_BYTES = 32
    }
}

@Serializable
data class HybridEncryptedEnvelope(
    val algorithm: String,
    val ephemeralPublicKeyB64: String,
    val saltB64: String,
    val ciphertextB64: String,
    val ivB64: String,
    val senderDeviceId: String,
    val recipientDeviceId: String
)
