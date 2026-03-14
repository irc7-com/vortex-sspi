using System.Text;
using Vortex.Sspi;

Console.WriteLine("=== Vortex SSPI Test Server ===");

// Run IRCd-lite server in background
var ircdServer = new Vortex.Sspi.Test.LiteIrcdServer();
var ircTask = ircdServer.RunAsync();
Console.WriteLine("Press any key to shut down IRCd-lite server...");
Console.ReadKey();
ircdServer.RequestShutdown();
await ircTask;
