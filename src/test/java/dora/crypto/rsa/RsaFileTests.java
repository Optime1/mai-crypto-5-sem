package dora.crypto.rsa;

import dora.crypto.rsa.ProbabilisticTests.RsaFileCipher;
import dora.crypto.rsa.ProbabilisticTests.RsaService;
import net.jqwik.api.*;
import net.jqwik.api.lifecycle.AfterContainer;
import net.jqwik.api.lifecycle.BeforeContainer;

import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.AssertionsForClassTypes.assertThatThrownBy;

public class RsaFileTests {
    private static RsaService rsaService;
    private static RsaFileCipher rsaFileCipher;

    @BeforeContainer
    static void setUp() {
        rsaService = new RsaService(RsaService.PrimalityTest.MILLER_RABIN, 0.99, 2048);
        rsaFileCipher = new RsaFileCipher(rsaService);
    }

    @AfterContainer
    static void tearDown() {
        if (rsaFileCipher != null) {
            rsaFileCipher.shutdown();
        }
    }

    @Example
    void throwsExceptionIfMessageTooLarge() {
        BigInteger N = rsaService.getN();
        BigInteger tooLarge = N.add(BigInteger.ONE);

        assertThatThrownBy(() -> rsaService.encrypt(tooLarge))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Message must be less than N");
    }


    @Property(tries = 5)
    void fileEncryptionProperty(@ForAll("randomFileContent") byte[] fileContent) throws IOException, InterruptedException {
        Path inputFile = Files.createTempFile("jqwik_input", ".tmp");
        Path encryptedFile = Files.createTempFile("jqwik_enc", ".rsa");
        Path decryptedFile = Files.createTempFile("jqwik_dec", ".tmp");

        try {
            Files.write(inputFile, fileContent);

            rsaFileCipher.encryptFile(inputFile, encryptedFile);
            rsaFileCipher.decryptFile(encryptedFile, decryptedFile);

            byte[] resultBytes = Files.readAllBytes(decryptedFile);

            assertThat(resultBytes).isEqualTo(fileContent);
        } finally {
            Files.deleteIfExists(inputFile);
            Files.deleteIfExists(encryptedFile);
            Files.deleteIfExists(decryptedFile);
        }
    }

    @Provide
    Arbitrary<byte[]> randomFileContent() {
        return Arbitraries.bytes().array(byte[].class).ofMinSize(1024).ofMaxSize(10 * 1024);
    }

    @Example
    void integrationWithResourceFiles() throws IOException, InterruptedException {
        decryptFileTests(rsaFileCipher);
    }

    private void decryptFileTests(RsaFileCipher cipher) throws IOException, InterruptedException {
        decryptFileTest(cipher, "/allocator_red_black_tree_tests.cpp");
        decryptFileTest(cipher, "/code_pen.jpg");
        decryptFileTest(cipher, "/wireshark.jpg");
    }

    private void decryptFileTest(RsaFileCipher cipher, String resourcePath) throws IOException, InterruptedException {
        Path inputFile = null;
        Path encryptedFile = null;
        Path decryptedFile = null;

        try (InputStream stream = getClass().getResourceAsStream(resourcePath)) {
            byte[] inputBytes;

            inputBytes = stream.readAllBytes();

            inputFile = Files.createTempFile("input", null);
            encryptedFile = Files.createTempFile("encrypted", null);
            decryptedFile = Files.createTempFile("decrypted", null);

            Files.write(inputFile, inputBytes);

            cipher.encryptFile(inputFile, encryptedFile);
            cipher.decryptFile(encryptedFile, decryptedFile);

            byte[] outputBytes = Files.readAllBytes(decryptedFile);

            assertThat(outputBytes).isEqualTo(inputBytes);

        } finally {
            if (inputFile != null) Files.deleteIfExists(inputFile);
            if (encryptedFile != null) Files.deleteIfExists(encryptedFile);
            if (decryptedFile != null) Files.deleteIfExists(decryptedFile);
        }
    }
}