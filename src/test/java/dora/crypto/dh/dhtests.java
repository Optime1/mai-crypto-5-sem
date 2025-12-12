package dora.crypto.dh;

import dora.crypto.SymmetricCipher;
import dora.crypto.SymmetricCipher.CipherModeType;
import dora.crypto.SymmetricCipher.PaddingType;
import dora.crypto.block.rijndael.RijndaelBlockCipher;
import dora.crypto.block.rijndael.RijndaelParameters;
import dora.crypto.block.rijndael.RijndaelParameters.BlockSize;
import dora.crypto.block.rijndael.RijndaelParameters.KeySize;
import net.jqwik.api.*;
import net.jqwik.api.constraints.Size;

import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.assertj.core.api.Assertions.assertThat;

class dhTests {

    // Безопасные параметры группы (RFC 3526, 2048-bit MODP Group)
    private static final BigInteger P_RFC3526 = new BigInteger(
            "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1" +
                    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD" +
                    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245" +
                    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" +
                    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D" +
                    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F" +
                    "83655D23DCA3AD961C62F356208552BB9ED529077096966D" +
                    "670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF", 16);

    private static final BigInteger G_RFC3526 = BigInteger.valueOf(2);

    private static final short AES_POLYNOMIAL = 0x11B;

    @Example
    void diffieHellmanKeyExchangeWithRijndaelEncryption(
            @ForAll @Size(value = 16) byte[] iv
    ) throws IOException, InterruptedException {

        DiffieHellmanProtocol alice = new DiffieHellmanProtocol(P_RFC3526, G_RFC3526);
        DiffieHellmanProtocol bob = new DiffieHellmanProtocol(P_RFC3526, G_RFC3526);

        BigInteger alicePublic = alice.getPublicKey();
        BigInteger bobPublic = bob.getPublicKey();

        byte[] aliceSharedKey = alice.deriveSymmetricKey(bobPublic);
        byte[] bobSharedKey = bob.deriveSymmetricKey(alicePublic);

        assertThat(aliceSharedKey).hasSize(32); // 256 бит
        assertThat(aliceSharedKey).isEqualTo(bobSharedKey);


        SymmetricCipher aliceCipher = SymmetricCipher.builder()
                .cipher(new RijndaelBlockCipher(
                        new RijndaelParameters(KeySize.KEY_256, BlockSize.BLOCK_128, AES_POLYNOMIAL)
                ))
                .mode(CipherModeType.CBC)
                .padding(PaddingType.PKCS7)
                .key(aliceSharedKey)
                .iv(iv)
                .build();

        SymmetricCipher bobCipher = SymmetricCipher.builder()
                .cipher(new RijndaelBlockCipher(
                        new RijndaelParameters(KeySize.KEY_256, BlockSize.BLOCK_128, AES_POLYNOMIAL)
                ))
                .mode(CipherModeType.CBC)
                .padding(PaddingType.PKCS7)
                .key(bobSharedKey)
                .iv(iv)
                .build();

        testEncryptionCycle(aliceCipher, bobCipher);
        testEncryptionCycle(bobCipher, aliceCipher);
    }

    private void testEncryptionCycle(SymmetricCipher encryptor, SymmetricCipher decryptor)
            throws IOException, InterruptedException {

        String resourcePath = "/code_pen.jpg";

        Path inputFile = null;
        Path encryptedFile = null;
        Path decryptedFile = null;

        try (InputStream stream = getClass().getResourceAsStream(resourcePath)) {
            byte[] inputBytes = stream.readAllBytes();

            inputFile = Files.createTempFile("dh_input", null);
            encryptedFile = Files.createTempFile("dh_encrypted", null);
            decryptedFile = Files.createTempFile("dh_decrypted", null);

            Files.write(inputFile, inputBytes);

            encryptor.encryptFile(inputFile, encryptedFile);

            decryptor.decryptFile(encryptedFile, decryptedFile);

            byte[] outputBytes = Files.readAllBytes(decryptedFile);

            assertThat(outputBytes).isEqualTo(inputBytes);

        } finally {
            if (inputFile != null) Files.deleteIfExists(inputFile);
            if (encryptedFile != null) Files.deleteIfExists(encryptedFile);
            if (decryptedFile != null) Files.deleteIfExists(decryptedFile);
        }
    }
}