namespace Dora.Crypto.Block.Rijndael;

using System;

/// <summary>
/// Параметры алгоритма Rijndael (размеры ключа и блока, модуль, S-Box).
/// </summary>
public sealed class RijndaelParameters
{
    private static readonly short AesModulus = 0x11b; // x^8 + x^4 + x^3 + x + 1

    private readonly KeySize _keySize;
    private readonly BlockSize _blockSize;
    private readonly short _modulus;
    private readonly RijndaelSBox _sBox;
    private readonly RijndaelInverseSBox _inverseSBox;
    private readonly RijndaelRcon _rcon;

    public RijndaelParameters(KeySize keySize, BlockSize blockSize, short modulus)
    {
        var field = new GaloisField();
        if (!field.Irreducible(modulus))
            throw new ArgumentException("Modulus may not be reducible");

        _keySize = keySize ?? throw new ArgumentNullException(nameof(keySize));
        _blockSize = blockSize ?? throw new ArgumentNullException(nameof(blockSize));
        _modulus = modulus;
        _sBox = new RijndaelSBox(modulus);
        _inverseSBox = new RijndaelInverseSBox(modulus);
        _rcon = new RijndaelRcon(modulus, keySize.Words(), blockSize.Words(), Rounds());
    }

    #region Factory methods

    public static RijndaelParameters Aes128() 
        => new(KeySize.Key128, BlockSize.Block128, AesModulus);

    public static RijndaelParameters Aes192() 
        => new(KeySize.Key192, BlockSize.Block128, AesModulus);

    public static RijndaelParameters Aes256() 
        => new(KeySize.Key256, BlockSize.Block128, AesModulus);

    #endregion

    #region Getters

    public int Rounds() => Math.Max(_keySize.Words(), _blockSize.Words()) + 6;

    public RijndaelParameters.KeySize GetKeySize() => _keySize;

    public RijndaelParameters.BlockSize GetBlockSize() => _blockSize;

    public short Modulus() => _modulus;

    public RijndaelSBox SBox() => _sBox;

    public RijndaelInverseSBox InverseSBox() => _inverseSBox;

    public byte[][] Rcon() => _rcon.Value;

    #endregion

    public sealed class KeySize
    {
        public static readonly KeySize Key128 = new(16);
        public static readonly KeySize Key192 = new(24);
        public static readonly KeySize Key256 = new(32);

        private readonly int _bytes;

        private KeySize(int bytes) => _bytes = bytes;

        public int Bytes() => _bytes;

        public int Words() => _bytes / 4;

        public static KeySize OfBytes(int bytes)
        {
            if (bytes == 16) return Key128;
            if (bytes == 24) return Key192;
            if (bytes == 32) return Key256;
            throw new ArgumentException("Invalid key size");
        }
    }

    public sealed class BlockSize
    {
        public static readonly BlockSize Block128 = new(16);
        public static readonly BlockSize Block192 = new(24);
        public static readonly BlockSize Block256 = new(32);

        private readonly int _bytes;

        private BlockSize(int bytes) => _bytes = bytes;

        public int Bytes() => _bytes;

        public int Words() => _bytes / 4;

        public static BlockSize OfBytes(int bytes)
        {
            if (bytes == 16) return Block128;
            if (bytes == 24) return Block192;
            if (bytes == 32) return Block256;
            throw new ArgumentException("Invalid block size");
        }
    }
}
