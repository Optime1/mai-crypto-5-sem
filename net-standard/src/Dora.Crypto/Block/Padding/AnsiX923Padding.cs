using System;

namespace Dora.Crypto.Block.Padding;

public sealed class AnsiX923Padding : AbstractPadding
{
    protected override byte[] PaddingBytes(int remaining, int blockSize)
    {
        if (remaining == 0) return Array.Empty<byte>();

        byte[] padding = new byte[remaining];
        // Arrays.Fill с нулём не нужен, массив уже инициализирован нулями
        padding[remaining - 1] = (byte)remaining;

        return padding;
    }

    protected override int PaddingSize(byte[] data, int blockSize)
    {
        return data[data.Length - 1] & 0xff;
    }
}
