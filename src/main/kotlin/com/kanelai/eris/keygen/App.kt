package com.kanelai.eris.keygen

import net.i2p.crypto.eddsa.EdDSAEngine
import net.i2p.crypto.eddsa.EdDSAPrivateKey
import net.i2p.crypto.eddsa.Utils
import net.i2p.crypto.eddsa.spec.EdDSANamedCurveTable
import net.i2p.crypto.eddsa.spec.EdDSAPrivateKeySpec
import org.bouncycastle.crypto.digests.RIPEMD160Digest
import java.security.MessageDigest
import java.util.*


object App {

    @JvmStatic
    fun main(argv: Array<String>) {
        // Ed25519 to generate Eris key pair
        //val seed = Utils.hexToBytes("CFCC6951976F78D797B5DDDBC59A52A6C595D17A3D0EDDE8A1C5E41CC0397E18")
        val seed = ByteArray(32)
        Random().nextBytes(seed)
        val ed25519 = EdDSANamedCurveTable.getByName("Ed25519")
        val privKeySpec = EdDSAPrivateKeySpec(seed, ed25519)
        println("Seed        : " + Utils.bytesToHex(privKeySpec.seed).toUpperCase())
        val privKey = EdDSAPrivateKey(privKeySpec)
        val erisPubKey = privKey.abyte
        val erisPrivKey = privKeySpec.seed + privKey.abyte
        println("Public key  : " + Utils.bytesToHex(erisPubKey).toUpperCase())
        println("Private key : " + Utils.bytesToHex(erisPrivKey).toUpperCase())

        // RipeMD to generate Eris address
        val digest = RIPEMD160Digest()
        digest.update(byteArrayOf(0x01, 0x01, 0x20), 0, 3)
        digest.update(privKey.abyte, 0, privKey.abyte.size)
        val erisAddr = ByteArray(digest.digestSize)
        digest.doFinal(erisAddr, 0)
        println("Address     : " + Utils.bytesToHex(erisAddr).toUpperCase())

        // Ed25519 to sign message
        val messageToSign = "Hello Marmots!"
        println("Message to sign: " + messageToSign)
        val signer = EdDSAEngine(MessageDigest.getInstance(ed25519.hashAlgorithm))
        signer.initSign(privKey)
        signer.update(messageToSign.toByteArray(Charsets.UTF_8))
        println("Signature   : " + Utils.bytesToHex(signer.sign()).toUpperCase())
    }

}
