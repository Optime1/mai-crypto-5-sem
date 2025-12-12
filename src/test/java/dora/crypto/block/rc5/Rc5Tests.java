package dora.crypto.block.rc5;

import dora.crypto.SymmetricCipher;
import dora.crypto.SymmetricCipher.CipherModeType;
import dora.crypto.SymmetricCipher.PaddingType;
import net.jqwik.api.*;
import net.jqwik.api.constraints.Positive;
import net.jqwik.api.constraints.Size;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.assertj.core.api.Assertions.assertThat;

public class Rc5Tests {

    @Example
    void decryptFile_RC5_CBC_Pkcs7Padding(
            @ForAll @Size(value = 16) byte[] key,
            @ForAll @Size(value = 8) byte[] iv
    ) throws IOException, InterruptedException {
        decryptFileTests(
                SymmetricCipher.builder()
                        .cipher(new Rc5BlockCipher())
                        .mode(CipherModeType.CBC)
                        .padding(PaddingType.PKCS7)
                        .key(key)
                        .iv(iv)
                        .build()
        );
    }

    @Example
    void decryptFile_RC5_20Rounds_ECB_AnsiX923Padding(
            @ForAll @Size(value = 32) byte[] key
    ) throws IOException, InterruptedException {
        decryptFileTests(
                SymmetricCipher.builder()
                        .cipher(new Rc5BlockCipher(20))
                        .mode(CipherModeType.ECB)
                        .padding(PaddingType.ANSI_X923)
                        .key(key)
                        .build()
        );
    }

    @Example
    void decryptFile_RC5_CTR_Iso10126Padding(
            @ForAll @Size(value = 16) byte[] key,
            @ForAll @Size(value = 4) byte[] nonce,
            @ForAll @Positive int counter
    ) throws IOException, InterruptedException {
        decryptFileTests(
                SymmetricCipher.builder()
                        .cipher(new Rc5BlockCipher())
                        .mode(CipherModeType.CTR)
                        .padding(PaddingType.ISO_10126)
                        .key(key)
                        .iv(nonce)
                        .argument(counter)
                        .build()
        );
    }

    @Property
    void rc5BlockProperty(@ForAll @Size(16) byte[] key, @ForAll @Size(8) byte[] block) {
        Rc5BlockCipher cipher = new Rc5BlockCipher();
        cipher.init(key);

        byte[] encrypted = cipher.encrypt(block);
        byte[] decrypted = cipher.decrypt(encrypted);

        assertThat(decrypted).isEqualTo(block);
        if (!isAllZeros(block)) {
            assertThat(encrypted).isNotEqualTo(block);
        }
    }

    private boolean isAllZeros(byte[] array) {
        for (byte b : array) if (b != 0) return false;
        return true;
    }

    private void decryptFileTests(SymmetricCipher cipher) throws IOException, InterruptedException {
        decryptFileTest(cipher, "/allocator_red_black_tree_tests.cpp");
        decryptFileTest(cipher, "/code_pen.jpg");
        decryptFileTest(cipher, "/wireshark.jpg");
    }

    private void decryptFileTest(SymmetricCipher cipher, String resourcePath) throws IOException, InterruptedException {
        Path inputFile = null;
        Path encryptedFile = null;
        Path decryptedFile = null;

        try (InputStream stream = getClass().getResourceAsStream(resourcePath)) {
            byte[] inputBytes;

            inputBytes = stream.readAllBytes();

            inputFile = Files.createTempFile("rc5_in", null);
            encryptedFile = Files.createTempFile("rc5_enc", null);
            decryptedFile = Files.createTempFile("rc5_dec", null);

            Files.write(inputFile, inputBytes);

            cipher.encryptFile(inputFile, encryptedFile);
            cipher.decryptFile(encryptedFile, decryptedFile);

            byte[] outputBytes = Files.readAllBytes(decryptedFile);
            assertThat(inputBytes).isEqualTo(outputBytes);

        } finally {
            if (inputFile != null) Files.deleteIfExists(inputFile);
            if (encryptedFile != null) Files.deleteIfExists(encryptedFile);
            if (decryptedFile != null) Files.deleteIfExists(decryptedFile);
        }
    }
}