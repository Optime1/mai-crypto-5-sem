package dora.crypto.rc4;

import dora.crypto.rsa.ProbabilisticTests.FileCipher;
import org.jetbrains.annotations.NotNull;

import java.io.*;
import java.nio.file.Path;
import java.util.concurrent.*;

public class Rc4FileCipher implements FileCipher {

    private final byte[] key;
    private final ExecutorService executorService;

    private static final int BUFFER_SIZE = 64 * 1024;

    public Rc4FileCipher(byte @NotNull [] key) {
        this.key = key;
        this.executorService = Executors.newSingleThreadExecutor();
    }

    @Override
    public void encryptFile(@NotNull Path inputFile, @NotNull Path outputFile) throws IOException, InterruptedException, ExecutionException {
        processFileAsync(inputFile, outputFile).get();
    }

    @Override
    public void decryptFile(@NotNull Path inputFile, @NotNull Path outputFile) throws IOException, InterruptedException, ExecutionException {
        processFileAsync(inputFile, outputFile).get();
    }

    public CompletableFuture<Void> processFileAsync(Path inputPath, Path outputPath) {
        return CompletableFuture.runAsync(() -> {
            try {
                processFileInternal(inputPath.toFile(), outputPath.toFile());
            } catch (IOException e) {
                throw new CompletionException(e);
            }
        }, executorService);
    }

    private void processFileInternal(File inputFile, File outputFile) throws IOException {
        Rc4Engine engine = new Rc4Engine(key);

        try (BufferedInputStream bis = new BufferedInputStream(new FileInputStream(inputFile));
             BufferedOutputStream bos = new BufferedOutputStream(new FileOutputStream(outputFile))) {

            byte[] buffer = new byte[BUFFER_SIZE];
            int bytesRead;

            while ((bytesRead = bis.read(buffer)) != -1) {
                byte[] chunk;
                if (bytesRead < BUFFER_SIZE) {
                    chunk = new byte[bytesRead];
                    System.arraycopy(buffer, 0, chunk, 0, bytesRead);
                } else {
                    chunk = buffer;
                }

                byte[] processed = engine.process(chunk);

                bos.write(processed);
            }
        }
    }

    public void shutdown() {
        executorService.shutdown();
    }
}