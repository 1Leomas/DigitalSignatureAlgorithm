using System.Numerics;

namespace DigitalSignatureAlgorithm;

internal class KeyGeneration
{
    public BigInteger GeneratePrivateKey(BigInteger q)
    {
        var rbi = new BigIntHelper();
        return rbi.RandomBigInteger(1, q - 1); //private key should be < Q
    }

    public BigInteger GeneratePublicKey(BigInteger privateKey, BigInteger g, BigInteger p)
    {
        return BigInteger.ModPow(g, privateKey, p);
    }
}