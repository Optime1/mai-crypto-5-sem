namespace Dora.Crypto.Block;

public interface IBlockCipher
{
    int BlockSize { get; }
    void Init(byte[] key);
    byte[] Encrypt(byte[] plaintext);
    byte[] Decrypt(byte[] ciphertext);
}
