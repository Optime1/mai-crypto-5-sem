package dora.crypto.rsa.ProbabilisticTests;

import org.jetbrains.annotations.NotNull;

import java.io.*;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.file.Path;
import java.util.concurrent.*;

public class RsaFileCipher implements FileCipher {

    private final RsaService rsaService;
    private final ExecutorService executorService;
    private static final int HEADER_SIZE = 4;

    private static final int QUEUE_CAPACITY = 400;

    private static final Future<byte[]> POISON_PILL = CompletableFuture.completedFuture(new byte[0]);

    public RsaFileCipher(@NotNull RsaService rsaService) {
        this.rsaService = rsaService;
        this.executorService = Executors.newFixedThreadPool(Runtime.getRuntime().availableProcessors());
    }

    @Override
    public void encryptFile(@NotNull Path inputFile, @NotNull Path outputFile) throws IOException, InterruptedException {
        try {
            encryptFileAsync(inputFile.toFile(), outputFile.toFile()).get();
        } catch (ExecutionException e) {
            handleExecutionException(e);
        }
    }

    @Override
    public void decryptFile(@NotNull Path inputFile, @NotNull Path outputFile) throws IOException, InterruptedException {
        try {
            decryptFileAsync(inputFile.toFile(), outputFile.toFile()).get();
        } catch (ExecutionException e) {
            handleExecutionException(e);
        }
    }

    private void handleExecutionException(ExecutionException e) throws IOException {
        Throwable cause = e.getCause();
        if (cause instanceof IOException) {
            throw (IOException) cause;
        } else {
            throw new IOException("Encryption/Decryption failed unexpectedly", cause);
        }
    }

    public CompletableFuture<Void> encryptFileAsync(File inputFile, File outputFile) {
        return CompletableFuture.runAsync(() -> {
            try {
                encryptFileInternal(inputFile, outputFile);
            } catch (Exception e) {
                throw new CompletionException(e);
            }
        }, executorService);
    }

    public CompletableFuture<Void> decryptFileAsync(File inputFile, File outputFile) {
        return CompletableFuture.runAsync(() -> {
            try {
                decryptFileInternal(inputFile, outputFile);
            } catch (Exception e) {
                throw new CompletionException(e);
            }
        }, executorService);
    }

    private void encryptFileInternal(File inputFile, File outputFile) throws IOException, ExecutionException, InterruptedException {
        int maxBlockSize = (rsaService.getN().bitLength() / 8) - 2;
        if (maxBlockSize <= 0) throw new IllegalStateException("RSA key too small");

        BlockingQueue<Future<byte[]>> queue = new ArrayBlockingQueue<>(QUEUE_CAPACITY);

        CompletableFuture<Void> writerTask = CompletableFuture.runAsync(() -> {
            try (BufferedOutputStream bos = new BufferedOutputStream(new FileOutputStream(outputFile))) {
                while (true) {
                    Future<byte[]> future = queue.take();

                    if (future == POISON_PILL) break;

                    byte[] encryptedBlock = future.get();

                    bos.write(ByteBuffer.allocate(HEADER_SIZE).putInt(encryptedBlock.length).array());
                    bos.write(encryptedBlock);
                }
            } catch (Exception e) {
                throw new CompletionException(e);
            }
        }, executorService);

        try (BufferedInputStream bis = new BufferedInputStream(new FileInputStream(inputFile))) {
            byte[] buffer = new byte[maxBlockSize];
            int bytesRead;

            while ((bytesRead = bis.read(buffer)) != -1) {
                byte[] chunk;
                if (bytesRead < maxBlockSize) {
                    chunk = new byte[bytesRead];
                    System.arraycopy(buffer, 0, chunk, 0, bytesRead);
                } else {
                    chunk = buffer.clone();
                }

                Future<byte[]> task = executorService.submit(() -> encryptBlock(chunk));

                queue.put(task);
            }
        } catch (Exception e) {
            writerTask.cancel(true);
            throw e;
        } finally {
            queue.put(POISON_PILL);
        }

        writerTask.get();
    }

    private void decryptFileInternal(File inputFile, File outputFile) throws IOException, ExecutionException, InterruptedException {
        BlockingQueue<Future<byte[]>> queue = new ArrayBlockingQueue<>(QUEUE_CAPACITY);

        CompletableFuture<Void> writerTask = CompletableFuture.runAsync(() -> {
            try (BufferedOutputStream bos = new BufferedOutputStream(new FileOutputStream(outputFile))) {
                while (true) {
                    Future<byte[]> future = queue.take();
                    if (future == POISON_PILL) break;
                    bos.write(future.get());
                }
            } catch (Exception e) {
                throw new CompletionException(e);
            }
        }, executorService);

        try (BufferedInputStream bis = new BufferedInputStream(new FileInputStream(inputFile))) {
            while (bis.available() > 0) {
                byte[] lenBytes = new byte[HEADER_SIZE];
                int read = bis.read(lenBytes);
                if (read < HEADER_SIZE) break;

                int blockSize = ByteBuffer.wrap(lenBytes).getInt();
                byte[] encryptedData = new byte[blockSize];
                int dataRead = bis.read(encryptedData);
                if (dataRead < blockSize) throw new IOException("Unexpected end of file");

                Future<byte[]> task = executorService.submit(() -> decryptBlock(encryptedData));

                queue.put(task);
            }
        } catch (Exception e) {
            writerTask.cancel(true);
            throw e;
        } finally {
            queue.put(POISON_PILL);
        }

        writerTask.get();
    }

    private byte[] encryptBlock(byte[] data) {
        byte[] dataWithMarker = new byte[data.length + 1];
        dataWithMarker[0] = 1;
        System.arraycopy(data, 0, dataWithMarker, 1, data.length);
        return rsaService.encrypt(new BigInteger(1, dataWithMarker)).toByteArray();
    }

    private byte[] decryptBlock(byte[] encryptedData) {
        BigInteger c = new BigInteger(1, encryptedData);
        BigInteger m = rsaService.decrypt(c);
        byte[] decryptedWithMarker = m.toByteArray();
        int start = (decryptedWithMarker[0] == 0) ? 1 : 0;

        int len = decryptedWithMarker.length - start - 1;
        byte[] originalData = new byte[len];
        System.arraycopy(decryptedWithMarker, start + 1, originalData, 0, len);
        return originalData;
    }

    public void shutdown() {
        executorService.shutdown();
    }
}