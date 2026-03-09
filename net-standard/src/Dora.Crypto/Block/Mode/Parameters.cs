namespace Dora.Crypto.Block.Mode;

/// <summary>
/// Marker interface for cipher mode parameters.
/// </summary>
public interface IParameters
{
}

/// <summary>
/// No parameters required for this cipher mode.
/// </summary>
public sealed class NoParameters : IParameters
{
}

/// <summary>
/// Initialization Vector parameters.
/// </summary>
public sealed class IvParameters : IParameters
{
    public byte[] Iv { get; }

    public IvParameters(byte[] iv)
    {
        Iv = iv ?? throw new System.ArgumentNullException(nameof(iv));
    }
}
