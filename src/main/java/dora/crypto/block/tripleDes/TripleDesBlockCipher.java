package dora.crypto.block.tripleDes;

import dora.crypto.block.BlockCipher;
import org.jetbrains.annotations.NotNull;

public final class TripleDesBlockCipher implements BlockCipher {

    private final TripleDesKeySchedule keySchedule = new TripleDesKeySchedule();
    private final TripleDesEngine engine = new TripleDesEngine();
    private byte[][] roundKeys;

    @Override
    public int blockSize() {
        return 8; // DES block always 64 bit
    }

    @Override
    public void init(byte @NotNull [] key) {
        this.roundKeys = keySchedule.roundKeys(key);
    }

    @Override
    public byte[] encrypt(byte @NotNull [] plaintext) {
        if (roundKeys == null) {
            throw new IllegalStateException("Cipher not initialized");
        }
        return engine.encryptBlock(plaintext, roundKeys);
    }

    @Override
    public byte[] decrypt(byte @NotNull [] ciphertext) {
        if (roundKeys == null) {
            throw new IllegalStateException("Cipher not initialized");
        }
        return engine.decryptBlock(ciphertext, roundKeys);
    }
}