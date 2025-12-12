package dora.crypto.rc4;

import dora.crypto.rsa.ProbabilisticTests.FileCipher;
import net.jqwik.api.*;
import net.jqwik.api.constraints.Size;
import org.jetbrains.annotations.NotNull;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.ExecutionException;

import static org.assertj.core.api.Assertions.assertThat;

public class Rc4Tests {

    @Property(tries = 20)
    void rc4CorrectnessProperty(
            @ForAll @Size(min = 1, max = 256) byte[] key,
            @ForAll @Size(max = 10000) byte[] message
    ) {
        Rc4Engine encryptor = new Rc4Engine(key);
        byte[] ciphertext = encryptor.process(message);

        Rc4Engine decryptor = new Rc4Engine(key);
        byte[] decrypted = decryptor.process(ciphertext);

        assertThat(decrypted).isEqualTo(message);
    }

    @Property(tries = 5)
    void rc4FileEncryptionProperty(
            @ForAll @Size(min = 5, max = 32) byte[] key,
            @ForAll("randomFileContent") byte[] fileContent
    ) throws IOException, InterruptedException, ExecutionException {

        Rc4FileCipher cipher = new Rc4FileCipher(key);

        Path input = Files.createTempFile("rc4_in", ".tmp");
        Path enc = Files.createTempFile("rc4_enc", ".tmp");
        Path dec = Files.createTempFile("rc4_dec", ".tmp");

        try {
            Files.write(input, fileContent);

            cipher.encryptFile(input, enc);

            cipher.decryptFile(enc, dec);

            byte[] result = Files.readAllBytes(dec);

            assertThat(result).isEqualTo(fileContent);

            assertThat(Files.size(enc)).isEqualTo(fileContent.length);

        } finally {
            Files.deleteIfExists(input);
            Files.deleteIfExists(enc);
            Files.deleteIfExists(dec);
        }
    }

    @Provide
    Arbitrary<byte[]> randomFileContent() {
        return Arbitraries.bytes().array(byte[].class).ofMinSize(1).ofMaxSize(50 * 1024);
    }

    @Example
    void testResourceFiles(@ForAll @Size(16) byte[] key) throws IOException, InterruptedException {
        Rc4FileCipher cipher = new Rc4FileCipher(key);
        try {
            decryptFileTests(cipher);
        } finally {
            cipher.shutdown();
        }
    }

    private void decryptFileTests(@NotNull FileCipher cipher) throws IOException, InterruptedException {
        decryptFileTest(cipher, "/allocator_red_black_tree_tests.cpp");
        decryptFileTest(cipher, "/code_pen.jpg");
        decryptFileTest(cipher, "/wireshark.jpg");
    }

    private void decryptFileTest(FileCipher cipher, String resourcePath) throws IOException, InterruptedException {
        Path inputFile = null;
        Path encryptedFile = null;
        Path decryptedFile = null;

        try (InputStream stream = getClass().getResourceAsStream(resourcePath)) {
            byte[] inputBytes;
            if (stream == null) {
                inputBytes = ("Stub content for " + resourcePath).getBytes();
            } else {
                inputBytes = stream.readAllBytes();
            }

            inputFile = Files.createTempFile("input", null);
            encryptedFile = Files.createTempFile("encrypted", null);
            decryptedFile = Files.createTempFile("decrypted", null);

            Files.write(inputFile, inputBytes);

            cipher.encryptFile(inputFile, encryptedFile);
            cipher.decryptFile(encryptedFile, decryptedFile);

            byte[] outputBytes = Files.readAllBytes(decryptedFile);
            assertThat(outputBytes).isEqualTo(inputBytes);

        } catch (ExecutionException e) {
            throw new RuntimeException(e);
        } finally {
            if (inputFile != null) Files.deleteIfExists(inputFile);
            if (encryptedFile != null) Files.deleteIfExists(encryptedFile);
            if (decryptedFile != null) Files.deleteIfExists(decryptedFile);
        }
    }
}