using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Text.Json;
namespace GodAgent {
    class ResultSet {
        public string Type { get;set;}
        public object Data { get;set;}

        public string Report { get;set;}
        public List<string> order { get;set;}
        public ResultSet(string json) {
            loadJson(json);
        }
        bool loadJson(string json) {
            var root = JsonDocument.Parse(json).RootElement.GetProperty("module_result");
            string Type = root.GetProperty("Type").GetString();
            if (Type == "dict") {
                JsonElement order;
                List<string> listOrder = null;
                do {
                    if (root.TryGetProperty("Order", out order)) {
                        listOrder = new List<string>();
                        if (order.ValueKind == System.Text.Json.JsonValueKind.Null) {
                            break;
                        }
                        
                        foreach (var item in order.EnumerateArray()) {
                            listOrder.Add(item.GetString());
                        }
                    }
                } while (false);
                
                this.order = listOrder;
                var data = root.GetProperty("Data");
                var _result = new Dictionary<string, List<string>>();
                if (data.ToString() == "") {
                    this.Data = _result;
                    this.Type = "dict";
                }
                else {
                    foreach (var item in data.EnumerateObject()) {
                        List<string> _values = new List<string>();
                        foreach (var subItem in item.Value.EnumerateArray()) {
                            _values.Add(subItem.GetString());
                        }
                        _result[item.Name] = _values;
                    }
                    this.Data = _result;
                    this.Type = "dict";
                }
            } else if (Type == "array") {
                var data = root.GetProperty("Data");
                var _result = new List<string>();
                foreach (var item in data.EnumerateArray()) { 
                    _result.Add(item.GetString());
                }
                this.Data = _result;
                this.Type = "array";
            } else if (Type == "text_string") {
                this.Data = root.GetProperty("Data").GetString();
                this.Type = "text_string";
            } else if (Type == "error") {
                this.Data = root.GetProperty("Data").GetString();
                this.Type = "text_string";
            } else {
                this.Data = root.GetProperty("Data").ToString();
                this.Type = Type;
            }
            JsonElement report;
            if(root.TryGetProperty("Report",out report)) {
                this.Report = report.GetString();
                using StreamWriter file = new StreamWriter("Report.txt", append: true);
                file.Write(JsonSerializer.Serialize(this));
            }
            return true;
        }
    }

    class Module {
        public string Name { get;set;}
        public string Type { get;set;}
        public string Class { get;set;}
        public string Path { get;set;}
        public string Description { get;set;}
        //public Dictionary<string,string> Args { get;set;}
        public Module(string json) {
            loadJson(json);
        }
        public bool loadJson(string json) {
            JsonDocument jd = JsonDocument.Parse(json);
            string Name = jd.RootElement.GetProperty("Name").GetString();
            this.Name = Name;
            string Type = jd.RootElement.GetProperty("Type").GetString();
            this.Type = Type;
            string Class = jd.RootElement.GetProperty("Class").GetString();
            this.Class = Class;
            string Path = jd.RootElement.GetProperty("Path").GetString();
            this.Path = Path;
            string Description = jd.RootElement.GetProperty("Description").GetString();
            this.Description = Description;
            return true;
        }

        static private List<Module> GetListModule(string json) {
            List<Module> modules = new List<Module>();
            JsonDocument document = JsonDocument.Parse(json);
            var jsonModuleArray = document.RootElement.GetProperty("list_modules");
            foreach (var jsonModule in jsonModuleArray.EnumerateArray()) {
                modules.Add(new Module(jsonModule.ToString()));
            }
            return modules;
        }

        static public List<Module> GetModules() {
            GTGui.Message message = new GTGui.Message {
                command = "list_modules"
            };
            var client = new GTGui.ProcClient();
            string json = client.SendMessage(message);
            return GetListModule(json);
        }

        public ResultSet ModuleRun() {
            GTGui.Message message = new GTGui.Message {
                command = "run_module",
                module = this.Name
            };
            var client = new GTGui.ProcClient();
            string json = client.SendMessage(message);
            return new ResultSet(json);
        }
    }
}
