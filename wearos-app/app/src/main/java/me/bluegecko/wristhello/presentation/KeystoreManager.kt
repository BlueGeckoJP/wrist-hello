package me.bluegecko.wristhello.presentation

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.Signature

class KeystoreManager {
    private val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
    private val alias = "pc_unlock_ed25519_key"

    fun hasKey(): Boolean = keyStore.containsAlias(alias)

    fun getOrGenerateRawPublicKey(): ByteArray {
        if (!hasKey()) {
            val kpg = KeyPairGenerator.getInstance("Ed25519", "AndroidKeyStore")
            val spec = KeyGenParameterSpec.Builder(
                alias,
                KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
            )
                .setDigests(KeyProperties.DIGEST_NONE)
                .build()
            kpg.initialize(spec)
            kpg.generateKeyPair()
        }

        val certificate = keyStore.getCertificate(alias)
        val publicKey = certificate.publicKey

        // Remove X.509 ASN.1 Header (12 bytes)
        return publicKey.encoded.copyOfRange(12, 44)
    }

    fun signChallenge(challenge: ByteArray): ByteArray? {
        val privateKey = keyStore.getKey(alias, null) as PrivateKey
        val signature = Signature.getInstance("Ed25519")

        signature.initSign(privateKey)
        signature.update(challenge)

        return signature.sign()
    }
}