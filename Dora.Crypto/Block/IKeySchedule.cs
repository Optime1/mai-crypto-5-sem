namespace Dora.Crypto.Block;

public interface IKeySchedule
{
    byte[][] RoundKeys(byte[] key);
}
