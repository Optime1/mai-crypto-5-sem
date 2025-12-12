package dora.crypto.block.tripleDes;

import dora.crypto.block.des.DesBlockCipher;

public final class TripleDesEngine {

    public byte[] encryptBlock(byte[] block, byte[][] keys) {
        // Step 1: Encrypt with K1
        DesBlockCipher des1 = new DesBlockCipher();
        des1.init(keys[0]);
        byte[] step1 = des1.encrypt(block);

        // Step 2: Decrypt with K2
        DesBlockCipher des2 = new DesBlockCipher();
        des2.init(keys[1]);
        byte[] step2 = des2.decrypt(step1);

        // Step 3: Encrypt with K3
        DesBlockCipher des3 = new DesBlockCipher();
        des3.init(keys[2]);
        return des3.encrypt(step2);
    }

    public byte[] decryptBlock(byte[] block, byte[][] keys) {
        // Step 1: Decrypt with K3
        DesBlockCipher des3 = new DesBlockCipher();
        des3.init(keys[2]);
        byte[] step1 = des3.decrypt(block);

        // Step 2: Encrypt with K2
        DesBlockCipher des2 = new DesBlockCipher();
        des2.init(keys[1]);
        byte[] step2 = des2.encrypt(step1);

        // Step 3: Decrypt with K1
        DesBlockCipher des1 = new DesBlockCipher();
        des1.init(keys[0]);
        return des1.decrypt(step2);
    }
}