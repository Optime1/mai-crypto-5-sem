namespace Dora.Crypto.Block.Rijndael;

/// <summary>
/// Обратная таблица подстановки (Inverse S-Box) для Rijndael.
/// </summary>
public sealed class RijndaelInverseSBox
{
    private readonly byte[] _sBox = new byte[256];

    /// <summary>
    /// Инициализирует обратную S-Box Rijndael.
    /// </summary>
    /// <param name="modulus">Неприводимый модуль в GF(2^8).</param>
    internal RijndaelInverseSBox(short modulus)
    {
        var field = new GaloisField();
        Init(field, modulus);
    }

    public byte Lookup(byte b) => _sBox[b];

    private void Init(GaloisField field, short modulus)
    {
        for (int s = 0; s < 256; s++)
        {
            byte b = (byte)(RotateLeft((byte)s, 1) ^ RotateLeft((byte)s, 3) ^ RotateLeft((byte)s, 6) ^ 0x05);
            _sBox[s] = b == 0 ? (byte)0 : field.InvUnchecked(b, modulus);
        }
    }

    private static byte RotateLeft(byte b, int distance)
    {
        int i = b;
        return (byte)((i << distance) | (i >> (8 - distance)));
    }
}
