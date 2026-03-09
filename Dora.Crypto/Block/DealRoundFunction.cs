using System;
using Dora.Crypto.Block.Des;

namespace Dora.Crypto.Block;

/// <summary>
/// DEAL использует DES шифрование в качестве раундовой функции.
/// </summary>
public sealed class DealRoundFunction : IRoundFunction
{
    public byte[] Apply(byte[] block, byte[] key)
    {
        if (block == null) throw new ArgumentNullException(nameof(block));
        if (key == null) throw new ArgumentNullException(nameof(key));

        DesBlockCipher des = new DesBlockCipher();
        des.Init(key);
        return des.Encrypt(block);
    }
}
