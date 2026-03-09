using System;

namespace Dora.Crypto.Block.Padding;

public abstract class AbstractPadding : IPadding
{
    protected static readonly byte[] NoPadding = Array.Empty<byte>();

    public virtual byte[] Pad(byte[] data, int blockSize)
    {
        if (data == null) throw new ArgumentNullException(nameof(data));

        int remaining = blockSize - data.Length % blockSize;

        byte[] padding = PaddingBytes(remaining, blockSize);
        if (padding.Length == 0) return (byte[])data.Clone();

        byte[] padded = new byte[data.Length + padding.Length];
        Array.Copy(data, 0, padded, 0, data.Length);
        Array.Copy(padding, 0, padded, data.Length, padding.Length);

        return padded;
    }

    protected abstract byte[] PaddingBytes(int remaining, int blockSize);

    public virtual byte[] Unpad(byte[] data, int blockSize)
    {
        if (data == null) throw new ArgumentNullException(nameof(data));

        int paddingSize = PaddingSize(data, blockSize);

        if (paddingSize > blockSize)
        {
            throw new ArgumentException(
                "Data is not properly padded. Such issues can arise if the decryption failed.", nameof(data));
        }

        byte[] result = new byte[data.Length - paddingSize];
        Array.Copy(data, 0, result, 0, result.Length);
        return result;
    }

    protected abstract int PaddingSize(byte[] data, int blockSize);
}
