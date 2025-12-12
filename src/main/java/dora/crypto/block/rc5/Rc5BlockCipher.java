package dora.crypto.block.rc5;

import dora.crypto.block.BlockCipher;
import org.jetbrains.annotations.NotNull;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

/**
 * Implementation of the RC5 block cipher
 * Default parameters: w=32 (word size), r=12 (rounds), b=16 (key).
 * Block size: 64 bits (8 bytes).
 */
public class Rc5BlockCipher implements BlockCipher {

    private static final int W = 32; // Word size in bits
    private static final int BYTES_PER_WORD = W / 8;
    private static final int BLOCK_SIZE = 2 * BYTES_PER_WORD; // 8 bite

    // https://ru.wikipedia.org/wiki/RC5
    private static final int P32 = 0xB7E15163;
    private static final int Q32 = 0x9E3779B9;

    private int[] S; // Table of extended keys
    private final int rounds; // Number of rounds

    public Rc5BlockCipher() {
        this(12);
    }

    public Rc5BlockCipher(int rounds) {
        this.rounds = rounds;
    }

    @Override
    public int blockSize() {
        return BLOCK_SIZE;
    }

    public void init(byte @NotNull [] key) {
        keyExpansion(key);
    }

    @Override
    public byte[] encrypt(byte @NotNull [] block) {
        if (block.length != BLOCK_SIZE) {
            throw new IllegalArgumentException("RC5 block size must be " + BLOCK_SIZE + " bytes");
        }

        ByteBuffer buf = ByteBuffer.wrap(block).order(ByteOrder.LITTLE_ENDIAN);
        int A = buf.getInt();
        int B = buf.getInt();

        A = A + S[0];
        B = B + S[1];

        for (int i = 1; i <= rounds; i++) {
            A = Integer.rotateLeft(A ^ B, B) + S[2 * i];
            B = Integer.rotateLeft(B ^ A, A) + S[2 * i + 1];
        }

        byte[] output = new byte[BLOCK_SIZE];
        ByteBuffer outBuf = ByteBuffer.wrap(output).order(ByteOrder.LITTLE_ENDIAN);
        outBuf.putInt(A);
        outBuf.putInt(B);

        return output;
    }

    @Override
    public byte[] decrypt(byte @NotNull [] block) {
        if (block.length != BLOCK_SIZE) {
            throw new IllegalArgumentException("RC5 block size must be " + BLOCK_SIZE + " bytes");
        }

        ByteBuffer buf = ByteBuffer.wrap(block).order(ByteOrder.LITTLE_ENDIAN);
        int A = buf.getInt();
        int B = buf.getInt();

        for (int i = rounds; i >= 1; i--) {
            B = Integer.rotateRight(B - S[2 * i + 1], A) ^ A;
            A = Integer.rotateRight(A - S[2 * i], B) ^ B;
        }

        B = B - S[1];
        A = A - S[0];

        byte[] output = new byte[BLOCK_SIZE];
        ByteBuffer outBuf = ByteBuffer.wrap(output).order(ByteOrder.LITTLE_ENDIAN);
        outBuf.putInt(A);
        outBuf.putInt(B);

        return output;
    }


    private void keyExpansion(byte[] key) {
        int b = key.length;
        int u = BYTES_PER_WORD;
        int c = (Math.max(b, 1) + u - 1) / u;

        int[] L = new int[c];

        byte[] paddedKey = new byte[c * 4];
        System.arraycopy(key, 0, paddedKey, 0, b);
        ByteBuffer paddedBuf = ByteBuffer.wrap(paddedKey).order(ByteOrder.LITTLE_ENDIAN);
        for (int i = 0; i < c; i++) {
            L[i] = paddedBuf.getInt();
        }

        int t = 2 * (rounds + 1);
        S = new int[t];
        S[0] = P32;
        for (int i = 1; i < t; i++) {
            S[i] = S[i - 1] + Q32;
        }

        int i = 0, j = 0;
        int A = 0, B = 0;
        int loops = 3 * Math.max(t, c);

        for (int k = 0; k < loops; k++) {
            A = S[i] = Integer.rotateLeft(S[i] + A + B, 3);
            B = L[j] = Integer.rotateLeft(L[j] + A + B, A + B);
            i = (i + 1) % t;
            j = (j + 1) % c;
        }
    }
}