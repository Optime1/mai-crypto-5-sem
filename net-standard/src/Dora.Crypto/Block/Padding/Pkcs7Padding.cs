using System;

namespace Dora.Crypto.Block.Padding;

public sealed class Pkcs7Padding : AbstractPadding
{
    protected override byte[] PaddingBytes(int remaining, int blockSize)
    {
        if (remaining == 0) remaining = blockSize;
        byte[] padded = new byte[remaining];
        for (int i = 0; i < padded.Length; i++)
        {
            padded[i] = (byte)remaining;
        }
        return padded;
    }

    protected override int PaddingSize(byte[] data, int blockSize)
    {
        return data[data.Length - 1] & 0xff;
    }
}
