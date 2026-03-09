using System;
using Dora.Crypto.Block.Des;

namespace Dora.Crypto.Block;

/// <summary>
/// DEAL (Data Encryption Algorithm with Large block size)
/// Блочный шифр с размером блока 128 бит и переменным количеством раундов:
/// - 128-битный ключ: 6 раундов
/// - 192-битный ключ: 6 раундов  
/// - 256-битный ключ: 8 раундов
/// </summary>
public sealed class DealBlockCipher : FeistelBlockCipher
{
    public DealBlockCipher(byte[] desKey)
        : base(new DealKeySchedule(desKey), new DealRoundFunction(), 16)
    {
    }
}
