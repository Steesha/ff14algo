using ff14algo;
public class Program
{
    public static void Main()
    {
        string dynamicKey = "46558597235884622939";
        string password = "123456123456";

        Algorithm algo = new();
        string data = algo.LoginEncryption(password, dynamicKey);

        Console.WriteLine(data);
    }
}