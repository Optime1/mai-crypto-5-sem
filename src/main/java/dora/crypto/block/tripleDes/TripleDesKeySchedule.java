package dora.crypto.block.tripleDes;

import dora.crypto.block.KeySchedule;
import org.jetbrains.annotations.NotNull;
import java.util.Arrays;

public final class TripleDesKeySchedule implements KeySchedule {

    @Override
    public byte[][] roundKeys(byte @NotNull [] key) {
        byte[][] subKeys = new byte[3][8];

        if (key.length == 16) { // Option 2: K1, K2, K3=K1
            subKeys[0] = Arrays.copyOfRange(key, 0, 8);
            subKeys[1] = Arrays.copyOfRange(key, 8, 16);
            subKeys[2] = subKeys[0];
        } else if (key.length == 24) { // Option 1: K1, K2, K3
            subKeys[0] = Arrays.copyOfRange(key, 0, 8);
            subKeys[1] = Arrays.copyOfRange(key, 8, 16);
            subKeys[2] = Arrays.copyOfRange(key, 16, 24);
        } else {
            throw new IllegalArgumentException("Triple DES requires 128-bit or 192-bit key");
        }

        return subKeys;
    }
}