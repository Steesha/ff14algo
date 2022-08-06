using ff14algo;
public class Program
{
    public static void Main()
    {
        string dynamicKey = "46558597235884622939";
        string password = "123456123456";
        string data = Algorithm.LoginEncryption(password, dynamicKey);
        Console.WriteLine(data);
    }
}