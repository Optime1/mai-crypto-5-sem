using System;

namespace Dora.Crypto.Camellia;

/// <summary>
/// Реализация блочного шифра Camellia.
/// Поддерживает ключи длиной 128, 192 и 256 бит.
/// Размер блока: 128 бит (16 байт).
/// </summary>
public class CamelliaBlockCipher
{
    private readonly CamelliaKeySchedule _keySchedule;

    public CamelliaBlockCipher(byte[] key)
    {
        if (key == null || (key.Length != 16 && key.Length != 24 && key.Length != 32))
        {
            throw new ArgumentException("Ключ должен быть длиной 16, 24 или 32 байта (128, 192 или 256 бит).");
        }
        
        _keySchedule = new CamelliaKeySchedule(key);
    }

    /// <summary>
    /// Шифрование блока данных (16 байт).
    /// </summary>
    public void EncryptBlock(byte[] input, int inputOffset, byte[] output, int outputOffset)
    {
        ulong left = BytesToUlong(input, inputOffset);
        ulong right = BytesToUlong(input, inputOffset + 8);

        int rounds = _keySchedule.Rounds;
        
        for (int round = 0; round < rounds; round++)
        {
            // Применяем функцию раунда
            ulong subKey = _keySchedule.GetSubKey(round);
            ulong temp = F(right, subKey);
            ulong newLeft = left ^ temp;
            left = right;
            right = newLeft;

            // Каждые 6 раундов применяем функцию FL/FL^-1
            if ((round + 1) % 6 == 0 && round < rounds - 1)
            {
                ulong kl = _keySchedule.GetSubKey(rounds + (round / 6) * 2);
                ulong kr = _keySchedule.GetSubKey(rounds + (round / 6) * 2 + 1);
                
                if (((round + 1) / 6) % 2 == 1)
                {
                    // FL^-1 для расшифрования (но мы шифруем, поэтому используем FL)
                    (left, right) = FL(left, right, kl, kr);
                }
                else
                {
                    (left, right) = FL(left, right, kl, kr);
                }
            }
        }

        // Финальная перестановка
        ulong finalLeft = right;
        ulong finalRight = left;

        UlongToBytes(finalLeft, output, outputOffset);
        UlongToBytes(finalRight, output, outputOffset + 8);
    }

    /// <summary>
    /// Расшифрование блока данных (16 байт).
    /// </summary>
    public void DecryptBlock(byte[] input, int inputOffset, byte[] output, int outputOffset)
    {
        ulong left = BytesToUlong(input, inputOffset);
        ulong right = BytesToUlong(input, inputOffset + 8);

        int rounds = _keySchedule.Rounds;
        
        // Инвертированная начальная перестановка
        ulong temp = left;
        left = right;
        right = temp;

        for (int round = rounds - 1; round >= 0; round--)
        {
            // Каждые 6 раундов применяем функцию FL/FL^-1 перед основным раундом
            if ((round + 1) % 6 == 0 && round < rounds - 1)
            {
                ulong kl = _keySchedule.GetSubKey(rounds + (round / 6) * 2);
                ulong kr = _keySchedule.GetSubKey(rounds + (round / 6) * 2 + 1);
                
                (left, right) = FL_INV(left, right, kl, kr);
            }

            // Применяем обратную функцию раунда
            ulong subKey = _keySchedule.GetSubKey(round);
            ulong fResult = F(left, subKey);
            ulong newRight = right ^ fResult;
            right = left;
            left = newRight;
        }

        // Финальная перестановка
        ulong finalLeft = right;
        ulong finalRight = left;

        UlongToBytes(finalLeft, output, outputOffset);
        UlongToBytes(finalRight, output, outputOffset + 8);
    }

    /// <summary>
    /// Функция раунда Camellia.
    /// </summary>
    private ulong F(ulong x, ulong subKey)
    {
        ulong t = x ^ subKey;
        
        // Применяем S-блоки
        byte b0 = CamelliaConstants.S1((int)((t >> 56) & 0xFF));
        byte b1 = CamelliaConstants.S2((int)((t >> 48) & 0xFF));
        byte b2 = CamelliaConstants.S3((int)((t >> 40) & 0xFF));
        byte b3 = CamelliaConstants.S4((int)((t >> 32) & 0xFF));
        byte b4 = CamelliaConstants.S1((int)((t >> 24) & 0xFF));
        byte b5 = CamelliaConstants.S2((int)((t >> 16) & 0xFF));
        byte b6 = CamelliaConstants.S3((int)((t >> 8) & 0xFF));
        byte b7 = CamelliaConstants.S4((int)(t & 0xFF));

        // Перестановка P
        ulong result = 0;
        result |= ((ulong)(b0 ^ b2 ^ b4 ^ b6)) << 56;
        result |= ((ulong)(b1 ^ b3 ^ b5 ^ b7)) << 48;
        result |= ((ulong)(b0 ^ b1 ^ b4 ^ b5)) << 40;
        result |= ((ulong)(b2 ^ b3 ^ b6 ^ b7)) << 32;
        result |= ((ulong)(b0 ^ b3 ^ b4 ^ b7)) << 24;
        result |= ((ulong)(b1 ^ b2 ^ b5 ^ b6)) << 16;
        result |= ((ulong)(b0 ^ b1 ^ b2 ^ b3)) << 8;
        result |= ((ulong)(b4 ^ b5 ^ b6 ^ b7));

        return result;
    }

    /// <summary>
    /// Функция FL (линейное преобразование).
    /// </summary>
    private (ulong, ulong) FL(ulong left, ulong right, ulong kl, ulong kr)
    {
        ulong newRight = ((left & kl) << 1) | ((left & kl) >> 63);
        newRight ^= right;
        
        ulong newLeft = left ^ ((newRight | kr) << 1) | ((newRight | kr) >> 63);
        
        return (newLeft, newRight);
    }

    /// <summary>
    /// Обратная функция FL^-1.
    /// </summary>
    private (ulong, ulong) FL_INV(ulong left, ulong right, ulong kl, ulong kr)
    {
        ulong newLeft = left ^ (((right | kr) << 1) | ((right | kr) >> 63));
        
        ulong newRight = ((newLeft & kl) << 1) | ((newLeft & kl) >> 63);
        newRight ^= right;
        
        return (newLeft, newRight);
    }

    private static ulong BytesToUlong(byte[] bytes, int offset)
    {
        ulong result = 0;
        for (int i = 0; i < 8; i++)
        {
            result = (result << 8) | bytes[offset + i];
        }
        return result;
    }

    private static void UlongToBytes(ulong value, byte[] output, int offset)
    {
        for (int i = 7; i >= 0; i--)
        {
            output[offset + i] = (byte)(value & 0xFF);
            value >>= 8;
        }
    }
}
