package me.bluegecko.wristhello.presentation

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.Signature
import java.security.spec.ECGenParameterSpec

class KeystoreManager {
    private val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
    private val alias = "pc_unlock_ecdsa_key"

    fun hasKey(): Boolean = keyStore.containsAlias(alias)

    fun getOrGenerateRawPublicKey(): ByteArray {
        if (!hasKey()) {
            val kpg = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore")
            val spec = KeyGenParameterSpec.Builder(
                alias,
                KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
            )
                .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
                .setDigests(KeyProperties.DIGEST_SHA256)
                .build()
            kpg.initialize(spec)
            kpg.generateKeyPair()
        }

        val certificate = keyStore.getCertificate(alias)
        val publicKey = certificate.publicKey

        return publicKey.encoded
    }

    fun signChallenge(challenge: ByteArray): ByteArray? {
        val privateKey = keyStore.getKey(alias, null) as PrivateKey
        val signature = Signature.getInstance("SHA256withECDSA")

        signature.initSign(privateKey)
        signature.update(challenge)

        return signature.sign()
    }
}