using System.Numerics;

namespace DigitalSignatureAlgorithm;

internal class DomainParameters
{
    public BigInteger Q { get; private set; }
    public BigInteger P { get; private set; }
    public BigInteger H { get; private set; } // any value from 2 to p-2
    public BigInteger G { get; private set; }

    /// <param name="n">length of prime number</param>  
    /// <param name="l">key size</param>
    public DomainParameters(int n = 160, int l = 1024)
    {
        GenerateQ(n);       // 1. choose a prime number q of N bit
        GenerateP(l, Q);    // 2. choose a prime number p of L bit in such a way that p-1 is multiple of q.
        GenerateH(P);       // 3. choose h as an integer from the list (2...p-2).
        GenerateG(P, Q, H); // 4. compute g = h^((p-1)/q) mod p
    }

    public DomainParameters(int p, int q, int g)
    {
        P = p;
        Q = q;
        G = g;
    }

    private void GenerateQ(int n)
    {
        var rbi = new BigIntHelper();
        do
        {
            Q = rbi.NextBigInteger(n);
        } while (BigIntHelper.IsProbablePrime(Q, 100));
    }

    private void GenerateP(int l, BigInteger q)
    {
        if (l % 64 != 0)
            throw new ArgumentException("L must be a multiple of 64");
        
        var rbi = new BigIntHelper();
        do
        {
            P = rbi.NextBigInteger(l);

            var remainder = P % Q;

            P = P - remainder + BigInteger.One;

            while (!BigIntHelper.IsProbablePrime(P, 100))
            {
                P += q;
            }
        } while (P.ToByteArray().Length != l / 8); //P has to be l bits
    }

    public void GenerateH(BigInteger p)
    {
        var rbi = new BigIntHelper();
        H = rbi.RandomBigInteger(2, p - 2);
    }

    public void GenerateG(BigInteger p, BigInteger q, BigInteger h)
    {
        while (true)
        {
            G = BigInteger.ModPow(h, (p - 1) / q, p);

            if (G == 1)
            {
                GenerateH(p);
                continue;
            }

            break;
        }
    }
}