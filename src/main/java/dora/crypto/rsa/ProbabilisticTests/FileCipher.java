package dora.crypto.rsa.ProbabilisticTests;

import org.jetbrains.annotations.NotNull;

import java.io.IOException;
import java.nio.file.Path;
import java.util.concurrent.ExecutionException;

public interface FileCipher {
    void encryptFile(@NotNull Path inputFile, @NotNull Path encryptedFile) throws IOException, InterruptedException, ExecutionException;
    void decryptFile(@NotNull Path encryptedFile, @NotNull Path decryptedFile) throws IOException, InterruptedException, ExecutionException;
}