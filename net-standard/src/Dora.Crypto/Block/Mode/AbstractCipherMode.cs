using System;

namespace Dora.Crypto.Block.Mode;

using IBlockCipher = Dora.Crypto.Block.IBlockCipher;

public abstract class AbstractCipherMode : ICipherMode
{
    protected readonly IBlockCipher Cipher;
    protected readonly int BlockSizeValue;

    protected AbstractCipherMode(IBlockCipher cipher)
    {
        Cipher = cipher ?? throw new ArgumentNullException(nameof(cipher));
        BlockSizeValue = cipher.BlockSize;
    }

    public IBlockCipher Cipher => Cipher;

    public int BlockSize => BlockSizeValue;

    public virtual void Init(byte[] key, IParameters parameters)
    {
        if (key == null) throw new ArgumentNullException(nameof(key));
        Cipher.Init(key);
        InitMode(parameters ?? throw new ArgumentNullException(nameof(parameters)));
    }

    protected abstract void InitMode(IParameters parameters);

    public virtual byte[] Encrypt(byte[] plaintext)
    {
        if (plaintext == null) throw new ArgumentNullException(nameof(plaintext));

        if (plaintext.Length % BlockSize != 0)
            throw new ArgumentException("Plaintext not multiple of block size", nameof(plaintext));

        return EncryptBlocks(plaintext);
    }

    protected abstract byte[] EncryptBlocks(byte[] plaintext);

    public virtual byte[] Decrypt(byte[] ciphertext)
    {
        if (ciphertext == null) throw new ArgumentNullException(nameof(ciphertext));

        if (ciphertext.Length % BlockSize != 0)
            throw new ArgumentException("Ciphertext not multiple of block size", nameof(ciphertext));

        return DecryptBlocks(ciphertext);
    }

    protected abstract byte[] DecryptBlocks(byte[] ciphertext);
}
