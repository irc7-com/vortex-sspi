using System.Text;
using Vortex.Sspi;

Console.WriteLine("=== Vortex SSPI Bridge Test ===");

try 
{
    var session = new SspiSession();
    var testMessage = "Hello from C#!";
    byte[] input = Encoding.UTF8.GetBytes(testMessage);

    Console.WriteLine($"Sending: {testMessage}");

    byte[]? response = session.ProcessToken(input);

    if (response != null)
    {
        string result = Encoding.UTF8.GetString(response);
        Console.WriteLine($"Received from Rust: {result}");
    }
    else
    {
        Console.WriteLine("Error: Received null response from Rust.");
    }
}
catch (Exception ex)
{
    Console.WriteLine($"Critical Failure: {ex.Message}");
    Console.WriteLine(ex.StackTrace);
}

Console.WriteLine("===============================");