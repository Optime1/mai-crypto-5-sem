namespace Dora.Crypto.Block.Mode;

using IBlockCipher = Dora.Crypto.Block.IBlockCipher;

/// <summary>
/// Cipher mode wraps a <see cref="IBlockCipher"/> and operates on padded data to
/// provide encryption and decryption.
/// </summary>
public interface ICipherMode
{
    /// <summary>
    /// Returns the underlying block cipher.
    /// </summary>
    IBlockCipher Cipher { get; }

    /// <summary>
    /// Returns the cipher's block size. Useful for (un)padding data.
    /// </summary>
    int BlockSize { get; }

    /// <summary>
    /// Initializes the cipher mode.
    /// </summary>
    void Init(byte[] key, IParameters parameters);

    /// <summary>
    /// Encrypts padded data with the provided key.
    /// </summary>
    byte[] Encrypt(byte[] plaintext);

    /// <summary>
    /// Decrypts padded data with the provided key.
    /// </summary>
    byte[] Decrypt(byte[] ciphertext);
}
