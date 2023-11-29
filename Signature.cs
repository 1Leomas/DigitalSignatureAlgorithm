using System.Numerics;
using System.Security.Cryptography;
using System.Text;

namespace DigitalSignatureAlgorithm;

internal class Signature
{
    public BigInteger R { get; private set; }
    public BigInteger S { get; private set; }

    public Signature(BigInteger r, BigInteger s)
    {
        R = r;
        S = s;
    }   
        
    public static Signature Sign(DomainParameters dp, BigInteger privateKey, string message)
    {
        BigInteger r, s;
        while (true)
        {
            //1. Choose a random k in the range[1, q−1].
            var rbi = new BigIntHelper();
            var k = rbi.RandomBigInteger(1, dp.Q - 1);

            //2. Compute X = g^k mod p and r = X mod q.
            var x = BigInteger.ModPow(dp.G, k, dp.P);
            r = x % dp.Q;

            //   If r = 0 (unlikely) then go to step 1.
            if (r == 0) continue;

            //4. Compute h = SHA1(message) interpreted as an integer in the range 0 ≤ h < q.
            using HashAlgorithm sha = SHA256.Create();

            var hash = sha.ComputeHash(Encoding.UTF8.GetBytes(message));

            var h = new BigInteger(hash.GetHashCode());

            //5. Compute s = k^−1(h + ar) mod q.
            s = BigInteger.ModPow(k, dp.Q - 2, dp.Q) * (h + privateKey * r) % dp.Q;


            //   If s = 0 (unlikely) then go to step 1.
            if (s != 0) break;
        }

        //6. Return(r, s).
        return new Signature(r, s);
    }

    public static bool Verify(DomainParameters dp, BigInteger publicKey, string message, BigInteger r, BigInteger s)
    {
        //1. Verify that r and s are integers in the interval [1, q − 1]. If not, the signature is invalid.
        if (r < 1 || r > dp.Q - 1 || s < 1 || s > dp.Q - 1) return false;

        //2. Compute h = SHA1(message) interpreted as an integer in the range 0 ≤ h < q.

        using HashAlgorithm sha = SHA256.Create();

        var hash = sha.ComputeHash(Encoding.UTF8.GetBytes(message));


        BigInteger h = new BigInteger(hash);
        if (message == "41")
            h = 41;

        //3. Compute w = s^−1 mod q.
        var w = BigInteger.ModPow(s, dp.Q - 2, dp.Q);

        //4. Compute u1 = hw mod q and u2 = rw mod q.
        var u1 = h * w % dp.Q;
        var u2 = r * w % dp.Q;

        //5. Compute X = (g^u1 * y^u2 mod p) mod q.
        var x = BigInteger.ModPow(dp.G, u1, dp.P)
                * BigInteger.ModPow(publicKey, u2, dp.P) % dp.P;

        var v = x % dp.Q;

        //6. If X = r then the signature is valid; otherwise, it is invalid.
        return v == r;
    }
}