namespace Dora.Crypto.Block;

public interface IRoundFunction
{
    byte[] Apply(byte[] block, byte[] key);
}
