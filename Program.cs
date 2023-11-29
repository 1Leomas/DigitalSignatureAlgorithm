using DigitalSignatureAlgorithm;

NormalExecute();

//TestExecute();


Console.ReadLine();

void NormalExecute()
{
    var dp = new DomainParameters();

    Console.WriteLine($"Q: {dp.G}\n");
    Console.WriteLine($"P: {dp.P}\n");
    Console.WriteLine($"G: {dp.G}\n");

    var kg = new KeyGeneration();

    var privateKey = kg.GeneratePrivateKey(dp.Q);
    var publicKey = kg.GeneratePublicKey(privateKey, dp.G, dp.P);

    Console.WriteLine($"Private Key: {privateKey}\n");
    Console.WriteLine($"Public Key: {publicKey}\n");


    string message = "hello";

    var sign = Signature.Sign(dp, privateKey, message);

    Console.WriteLine($"r: {sign.R}\n");
    Console.WriteLine($"s: {sign.S}\n");

    var verify = Signature.Verify(dp, publicKey, message, sign.R, sign.S);

    Console.WriteLine($"Is signature valid? {verify}\n");
}
void TestExecute()
{
    var verify = Signature.Verify(new DomainParameters(283, 47, 60), 158, "41", 19, 30);
    Console.WriteLine($"Is signature valid? {verify}\n");
}