package dora.crypto.block.tripleDes;

import dora.crypto.block.BlockCipher;
import net.jqwik.api.*;
import net.jqwik.api.constraints.Size;

import static org.assertj.core.api.Assertions.assertThat;

public class TripleDesBlockCipherTest {

    @Property(tries = 1000)
    void decryptedCiphertextEqualsPlaintext(
            @ForAll @Size(value = 8) byte[] plaintext,
            @ForAll("tripleDesSizedKeys") byte[] key
    ) {
        BlockCipher cipher = new TripleDesBlockCipher();
        cipher.init(key);

        byte[] encrypted = cipher.encrypt(plaintext);
        byte[] decrypted = cipher.decrypt(encrypted);

        assertThat(decrypted).isEqualTo(plaintext);
    }

    @Provide
    Arbitrary<byte[]> tripleDesSizedKeys() {
        // 16 bite and 24 bite
        return Arbitraries.of(16, 24).flatMap(keySize ->
                Arbitraries.bytes().array(byte[].class).ofSize(keySize)
        );
    }
}