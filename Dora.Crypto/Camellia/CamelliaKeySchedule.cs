using System;

namespace Dora.Crypto.Camellia;

/// <summary>
/// Расписание ключей для алгоритма Camellia.
/// Поддерживает ключи длиной 128, 192 и 256 бит.
/// </summary>
public class CamelliaKeySchedule
{
    private readonly ulong[] _subKeys = new ulong[36]; // Максимум 36 подключей для 256-битного ключа
    private readonly int _keySize; // 128, 192 или 256
    private readonly int _rounds; // 18 для 128 бит, 24 для 192/256 бит

    public CamelliaKeySchedule(byte[] key)
    {
        _keySize = key.Length * 8;
        
        if (_keySize == 128)
        {
            _rounds = 18;
            GenerateSubKeys128(key);
        }
        else if (_keySize == 192 || _keySize == 256)
        {
            _rounds = 24;
            GenerateSubKeys256(key);
        }
        else
        {
            throw new ArgumentException($"Неподдерживаемая длина ключа: {_keySize} бит. Должно быть 128, 192 или 256.");
        }
    }

    public ulong GetSubKey(int index) => _subKeys[index];
    public int Rounds => _rounds;

    private void GenerateSubKeys128(byte[] key)
    {
        // Для 128-битного ключа
        ulong KL = BytesToUlong(key, 0);
        ulong KR = BytesToUlong(key, 8);

        ulong A = KL;
        ulong B = RotateLeft(KL, 15);
        ulong C = RotateLeft(KL, 30);
        ulong D = RotateLeft(KL, 64); // Фактически то же самое, что KL для 64-битных операций
        
        // Применяем функцию расписания ключей
        ulong T = A ^ B;
        T ^= CamelliaConstants.KS[0];
        T = ApplyF(T);
        
        // Генерируем подключи
        for (int i = 0; i < 9; i++)
        {
            _subKeys[i * 2] = RotateLeft(A, CamelliaConstants.KS[i * 2] & 0xFF);
            _subKeys[i * 2 + 1] = RotateLeft(B, CamelliaConstants.KS[i * 2 + 1] & 0xFF);
        }
    }

    private void GenerateSubKeys256(byte[] key)
    {
        // Для 192 и 256-битных ключей
        ulong KL = BytesToUlong(key, 0);
        ulong KR = BytesToUlong(key, 8);
        ulong KA, KB;

        if (_keySize == 192)
        {
            KR = ~KL; // Для 192 бит KR = NOT KL
        }
        else
        {
            KR = BytesToUlong(key, 8);
        }

        KA = KL ^ KR;
        KB = RotateLeft(KR, 15);

        ulong A = KA;
        ulong B = RotateLeft(KA, 15);
        ulong C = RotateLeft(KA, 30);
        ulong D = RotateLeft(KB, 15);

        // Применяем функцию расписания ключей
        ulong T = A ^ B;
        T ^= CamelliaConstants.KS[0];
        T = ApplyF(T);

        // Генерируем подключи
        for (int i = 0; i < 12; i++)
        {
            _subKeys[i * 3] = RotateLeft(KL, (int)(CamelliaConstants.KS[i * 3] & 0xFF));
            _subKeys[i * 3 + 1] = RotateLeft(KR, (int)(CamelliaConstants.KS[i * 3 + 1] & 0xFF));
            _subKeys[i * 3 + 2] = RotateLeft(KA, (int)(CamelliaConstants.KS[i * 3 + 2] & 0xFF));
        }
    }

    private ulong ApplyF(ulong x)
    {
        // Функция F расписания ключей
        ulong t = x;
        
        // Применяем S-блоки и перестановки
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

    private static ulong BytesToUlong(byte[] bytes, int offset)
    {
        ulong result = 0;
        for (int i = 0; i < 8; i++)
        {
            result = (result << 8) | bytes[offset + i];
        }
        return result;
    }

    private static ulong RotateLeft(ulong value, int shift)
    {
        shift &= 63; // Убедимся, что сдвиг в пределах 0-63
        return (value << shift) | (value >> (64 - shift));
    }
}
