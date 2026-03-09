namespace Dora.Crypto.Block.Padding;

/// <summary>
/// Padding interface for block cipher data.
/// </summary>
public interface IPadding
{
    byte[] Pad(byte[] data, int blockSize);
    byte[] Unpad(byte[] data, int blockSize);
}
