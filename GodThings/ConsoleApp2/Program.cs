using System;
using System.Diagnostics;
using System.IO;
using System.IO.Pipes;
using System.Security.Principal;
using System.Text;
using System.Threading;
using System.Text.Json;
namespace ConsoleApp2 {
    
    class Program {
        static void Main(string[] args) {
            var module_result = System.IO.File.ReadAllText(@"D:\windows\GodThings\GodThings\ConsoleApp2\module_result.json");
            var a = new ResultSet(module_result);
            Console.WriteLine(a);
            // Create Named Pipes
            //Message message = new Message {
            //    command = "run_module",
            //    module = "Process"
            //};

            //ProcClient procClient = ProcClient.GetClient();
            //string msg = procClient.SendMessage(message);
            //Console.WriteLine(msg);
            //ConsoleKeyInfo keyInfo = Console.ReadKey();
        }

        
    }
}
