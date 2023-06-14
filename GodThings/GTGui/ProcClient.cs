using System;
using System.Collections.Generic;
using System.Text;
using System.IO;
using System.IO.Pipes;
using System.Text.Json;

namespace GTGui {
    class Message {
        public string command { get; set; }
        public string module { get; set; }
        public object args { get; set; }
    }
    class ProcClient {
        NamedPipeClientStream stream;
        public ProcClient() {
            stream = new NamedPipeClientStream(".", "gtpipe", PipeDirection.InOut);
            stream.Connect();
        }

        public string SendMessage(Message message) {
            string jsonString = JsonSerializer.Serialize(message);
            byte[] writeBytes = Encoding.Default.GetBytes(jsonString);
            stream.Write(writeBytes, 0, writeBytes.Length);
            stream.WaitForPipeDrain();

            var reader = new StreamReader(stream);
            var msg = reader.ReadToEnd();
            return msg;
        }

        public static ProcClient _client = null;
        public static ProcClient GetClient() {
            if (_client == null) {
                _client = new ProcClient();
            }
            return _client;
        }
    }
}
