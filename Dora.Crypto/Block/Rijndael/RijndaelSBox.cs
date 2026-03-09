namespace Dora.Crypto.Block.Rijndael;

/// <summary>
/// Таблица подстановки (S-Box) для Rijndael.
/// </summary>
public sealed class RijndaelSBox
{
    private readonly byte[] _sBox = new byte[256];

    /// <summary>
    /// Инициализирует S-Box Rijndael.
    /// </summary>
    /// <param name="modulus">Неприводимый модуль в GF(2^8).</param>
    internal RijndaelSBox(short modulus)
    {
        var field = new GaloisField();
        Init(field, modulus);
    }

    public byte Lookup(byte b) => _sBox[b];

    private void Init(GaloisField field, short modulus)
    {
        for (int a = 0; a < _sBox.Length; a++)
        {
            byte b = a == 0 ? (byte)0 : field.InvUnchecked((byte)a, modulus);
            _sBox[a] = (byte)(b ^ RotateLeft(b, 1) ^ RotateLeft(b, 2) ^ RotateLeft(b, 3) ^ RotateLeft(b, 4) ^ 0x63);
        }
    }

    private static byte RotateLeft(byte b, int distance)
    {
        int i = b;
        return (byte)((i << distance) | (i >> (8 - distance)));
    }
}
