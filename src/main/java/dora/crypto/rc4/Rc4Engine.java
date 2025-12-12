package dora.crypto.rc4;

import org.jetbrains.annotations.NotNull;

public class Rc4Engine {

    private final byte[] S = new byte[256];
    private int x = 0;
    private int y = 0;

    /**
     * Key Scheduling Algorithm
     * Creates an initial state based on the key.
     */
    public Rc4Engine(byte @NotNull [] key) {
        if (key.length == 0 || key.length > 256) {
            throw new IllegalArgumentException("Key length must be between 1 and 256 bytes");
        }

        // Инициализация S-блока линейно
        for (int i = 0; i < 256; i++) {
            S[i] = (byte) i;
        }

        // Shuffling the S-block based on the key
        int j = 0;
        for (int i = 0; i < 256; i++) {
            j = (j + (S[i] & 0xFF) + (key[i % key.length] & 0xFF)) & 0xFF;
            swap(S, i, j);
        }
    }

    /**
     * Encryption/Byte Array Decryption.
     * RC4 is symmetric: XOR KeyStream = Data.
     * This method updates the internal state (x, y, S).
     */
    public byte[] process(byte @NotNull [] input) {
        byte[] output = new byte[input.length];

        for (int k = 0; k < input.length; k++) {
            x = (x + 1) & 0xFF;
            y = (y + (S[x] & 0xFF)) & 0xFF;

            swap(S, x, y);

            int t = ((S[x] & 0xFF) + (S[y] & 0xFF)) & 0xFF;
            byte keyStreamByte = S[t];

            output[k] = (byte) (input[k] ^ keyStreamByte);
        }
        return output;
    }

    private void swap(byte[] arr, int i, int j) {
        byte temp = arr[i];
        arr[i] = arr[j];
        arr[j] = temp;
    }
}