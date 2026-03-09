using System;
using Dora.Crypto.Block.Des;

namespace Dora.Crypto.Block;

/// <summary>
/// DEAL поддерживает ключи 128 бит, 192 бита и 256 бит.
/// Ключи 128 бит и 192 бит обеспечивают 6 раундов шифрования,
/// ключи 256 бит - 8 раундов.
/// </summary>
public sealed class DealKeySchedule : IKeySchedule
{
    private readonly DesBlockCipher _des;
    private readonly byte[] _desKey;

    public DealKeySchedule(byte[] desKey)
    {
        // Используем первые 8 байт как DES-ключ
        _desKey = new byte[8];
        Array.Copy(desKey, _desKey, 8);
        
        _des = new DesBlockCipher();
        _des.Init(_desKey);
    }

    public byte[][] RoundKeys(byte[] key)
    {
        if (key == null) throw new ArgumentNullException(nameof(key));

        int parts, rounds;

        switch (key.Length)
        {
            case 128 / 8:
                parts = 2;
                rounds = 6;
                break;
            case 192 / 8:
                parts = 3;
                rounds = 6;
                break;
            case 256 / 8:
                parts = 4;
                rounds = 8;
                break;
            default:
                throw new ArgumentException("Expected a 128-bit, 192-bit or a 256-bit key");
        }

        byte[][] keyParts = new byte[parts][];
        byte[][] roundKeys = new byte[rounds][];

        for (int i = 0; i < parts; i++)
        {
            keyParts[i] = new byte[8];
            Array.Copy(key, i * 8, keyParts[i], 0, 8);
        }

        roundKeys[0] = _des.Encrypt(keyParts[0]);
        for (int i = 1; i < parts; i++)
        {
            roundKeys[i] = _des.Encrypt(Xor(keyParts[i], roundKeys[i - 1]));
        }

        for (int k = parts; k < rounds; k++)
        {
            // Используем оборачивающиеся степени двойки для константного блока.
            byte[] constant = ToByteArray(1L << (k - parts));

            for (int i = 0; i < 8; i++)
            {
                roundKeys[k][i] = (byte)(keyParts[k % parts][i]
                                              ^ roundKeys[k - 1][i]
                                              ^ constant[i]);
            }
        }

        return roundKeys;
    }

    private static byte[] Xor(byte[] a, byte[] b)
    {
        byte[] result = new byte[a.Length];

        for (int i = 0; i < a.Length; i++)
        {
            result[i] = (byte)(a[i] ^ b[i]);
        }

        return result;
    }

    private static byte[] ToByteArray(long value)
    {
        return BitConverter.GetBytes(value);
    }
}
