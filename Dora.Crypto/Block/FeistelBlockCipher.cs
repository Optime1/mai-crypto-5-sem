using System;

namespace Dora.Crypto.Block;

public abstract class FeistelBlockCipher : IBlockCipher
{
    private readonly IKeySchedule _keySchedule;
    private readonly IRoundFunction _roundFunction;
    private readonly int _blockSize;
    private byte[][]? _roundKeys;

    protected FeistelBlockCipher(IKeySchedule keySchedule, IRoundFunction roundFunction, int blockSize)
    {
        _keySchedule = keySchedule ?? throw new ArgumentNullException(nameof(keySchedule));
        _roundFunction = roundFunction ?? throw new ArgumentNullException(nameof(roundFunction));
        _blockSize = blockSize;

        if (blockSize % 2 != 0)
        {
            throw new ArgumentException("Block size must be a multiple of two", nameof(blockSize));
        }
    }

    public int BlockSize() => _blockSize;

    public void Init(byte[] key)
    {
        _roundKeys = _keySchedule.RoundKeys(key ?? throw new ArgumentNullException(nameof(key)));
    }

    public virtual byte[] Encrypt(byte[] plaintext)
    {
        if (_roundKeys == null)
            throw new InvalidOperationException("Cipher is not initialized");
        
        var input = plaintext ?? throw new ArgumentNullException(nameof(plaintext));
        
        if (input.Length != _blockSize)
            throw new ArgumentException("Invalid block size", nameof(plaintext));

        // (1) Split the block into two equal parts.
        byte[] l = new byte[input.Length / 2];
        byte[] r = new byte[input.Length / 2];
        Array.Copy(input, 0, l, 0, l.Length);
        Array.Copy(input, input.Length / 2, r, 0, r.Length);

        // (2) For each round compute:
        //   - L_i+1 = R_i
        //   - R_i+1 = L_i xor F(R_i, K_i)
        foreach (var roundKey in _roundKeys)
        {
            byte[] rNew = new byte[r.Length];
            byte[] f = _roundFunction.Apply(r, roundKey);

            for (int k = 0; k < rNew.Length; k++)
            {
                rNew[k] = (byte)(l[k] ^ f[k]);
            }

            l = r;
            r = rNew;
        }

        // (3) The ciphertext is (R_n+1, L_n+1).
        byte[] ciphertext = new byte[input.Length];
        Array.Copy(r, 0, ciphertext, 0, r.Length);
        Array.Copy(l, 0, ciphertext, r.Length, l.Length);

        return ciphertext;
    }

    public virtual byte[] Decrypt(byte[] ciphertext)
    {
        if (_roundKeys == null)
            throw new InvalidOperationException("Cipher is not initialized");
        
        var input = ciphertext ?? throw new ArgumentNullException(nameof(ciphertext));
        
        if (input.Length != _blockSize)
            throw new ArgumentException("Invalid block size", nameof(ciphertext));

        // (1) Split the block into two equal parts.
        byte[] r = new byte[input.Length / 2];
        byte[] l = new byte[input.Length / 2];
        Array.Copy(input, 0, r, 0, r.Length);
        Array.Copy(input, input.Length / 2, l, 0, l.Length);

        // (2) For each round compute:
        //   - R_i = R_i+1
        //   - L_i = R_i+1 xor F(L_i+1, K_i)
        for (int i = _roundKeys.Length - 1; i >= 0; i--)
        {
            byte[] lNew = new byte[l.Length];
            byte[] f = _roundFunction.Apply(l, _roundKeys[i]);

            for (int k = 0; k < lNew.Length; k++)
            {
                lNew[k] = (byte)(r[k] ^ f[k]);
            }

            r = l;
            l = lNew;
        }

        // (3) The plaintext is (L_0, R_0).
        byte[] plaintext = new byte[input.Length];
        Array.Copy(l, 0, plaintext, 0, l.Length);
        Array.Copy(r, 0, plaintext, l.Length, r.Length);

        return plaintext;
    }
}
