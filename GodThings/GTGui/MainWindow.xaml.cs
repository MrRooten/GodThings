using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;
using System.Reflection;
using System.Threading;
using System.Text.Json;
using System.Data;
using System.IO;
using System.Runtime.Serialization.Formatters.Binary;
using System.Windows.Markup;

namespace GTGui {
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window {
        public TreeViewItem itemTreeRoot;
        private List<GodAgent.Module> mods;

        private void _RunModule(TreeViewItem item) {
            var name = item.Header.ToString();
            GodAgent.Module targetMod = null;
            foreach (var mod in mods) {
                if (mod.Name == name) {
                    targetMod = mod;
                    break;
                }
            }

            TabItem tabItem = new TabItem();
            tabItem.Header = targetMod.Name;
            
            var t = new Thread(() => {

                GodAgent.ResultSet result = targetMod.ModuleRun();
                object contentUI = null;
                if (result.Type == "dict") {
                    var table = new DataTable();
                    var dictData = (Dictionary<string, List<string>>)result.Data;
                    int length = 0;
                    List<string> fields = new List<string>();
                    if (result.order != null) {
                        foreach (var fieldName in result.order) {
                            length = dictData[fieldName].Count;
                            table.Columns.Add(fieldName);
                            fields.Add(fieldName);
                        }
                    }
                    else {
                        foreach (var fieldName in dictData.Keys) {
                            length = dictData[fieldName].Count();
                            table.Columns.Add(fieldName);
                            fields.Add(fieldName);
                        }
                    }
                    List<List<string>> list = new List<List<string>>();
                    foreach (var key in fields) {
                        list.Add(dictData[key]);
                    }
                    for (int i = 0; i < length; i++) {
                        List<string> _tmp = new List<string>();
                        for (int j = 0; j < list.Count(); j++) {
                            _tmp.Add(list[j][i]);
                        }
                        table.Rows.Add(_tmp.ToArray());
                    }
                    contentUI = table.DefaultView;
                }
                else if (result.Type == "text_string") {
                    var textBlock = new TextBlock();
                    textBlock.Text = (string)result.Data;
                    contentUI = textBlock;
                }
                else if (result.Type == "array") {
                    var table = new DataTable();
                    table.Columns.Add("Array Result");
                    var arrayData = (List<string>)result.Data;
                    foreach (var v in arrayData) {
                        string[] vs = { v };
                        table.Rows.Add(vs);
                    }
                    contentUI = table.AsDataView();
                }
                else if (result.Type == "error") {
                    var textBlock = new TextBlock();
                    textBlock.Text = (string)result.Data;
                    contentUI = textBlock;
                }
                else {

                }
                
                Dispatcher.Invoke(delegate {
                    if (result.Type == "dict") {
                        var grid = (DataGrid)FindResource("resultGrid");
                        var newGrid = new DataGrid();
                        newGrid.ItemsSource = (DataView)contentUI;
                        grid.DataContext = contentUI;
                        tabItem.Content = newGrid;
                    }
                    else if (result.Type == "array") {
                        var listView = (DataGrid)FindResource("resultGrid");
                        listView.DataContext = contentUI;
                        tabItem.Content = listView;
                    }
                    else {
                        var textBlock = new TextBlock();
                        textBlock.Text = (string)result.Data;
                        tabItem.Content = textBlock;
                    }
                    Tabs.Items.Add(tabItem);
                    Tabs.SelectedItem = tabItem;
                });

                
            });
            t.SetApartmentState(ApartmentState.STA);
            t.Start();

            return;
        }
        private void Item_DoubleClick(object sender, MouseButtonEventArgs e) {
            var item = (TreeViewItem)sender;
            _RunModule(item);
            return;
        }
        
        private void InitializeTreeItems() {
            var modules = GodAgent.Module.GetModules();
            this.mods = modules;
            Dictionary<string, List<GodAgent.Module>> tree = new Dictionary<string, List<GodAgent.Module>>();
            foreach (var module in modules) {
                if (tree.ContainsKey(module.Path)) {
                    tree[module.Path].Add(module); 
                } else {
                    tree.Add(module.Path, new List<GodAgent.Module>());
                    tree[module.Path].Add(module);
                }
                
            }
            var treeItemContextMenu = FindResource("treeItemContextMenu");
            foreach (var key in tree.Keys) {
                TreeViewItem parent = new TreeViewItem();
                parent.Header = key;
                foreach (var item in tree[key]) {
                    TreeViewItem moduleItem = new TreeViewItem();
                    moduleItem.Header = item.Name;
                    moduleItem.ContextMenu = (ContextMenu)treeItemContextMenu;
                    moduleItem.MouseDoubleClick +=  Item_DoubleClick;
                    parent.Items.Add(moduleItem);
                }
                ItemTree.Items.Add(parent);
            }

        }
        DataTable data;
        public MainWindow() {
            InitializeComponent();
            InitializeTreeItems();
            data = new DataTable();
            data.Columns.Add("id");
            data.Columns.Add("image");

            // create custom columns
            data.Columns.Add("Name1");
            data.Columns.Add("Name2");

            // add one row as an object array
            //data.Rows.Add(new object[] { 123, "image.png", "Foo", "Bar" });
            //grid.DataContext = data.DefaultView;
        }

        private void Run_Click(object sender, RoutedEventArgs e) {
            MenuItem menuItem = (MenuItem)sender;
            ContextMenu menu = menuItem.Parent as ContextMenu;
            TreeViewItem item = menu.PlacementTarget as TreeViewItem;
            _RunModule(item);
            
        }

        private void Property_Click(object sender, RoutedEventArgs e) {
            MenuItem menuItem = (MenuItem)sender;
            ContextMenu menu = menuItem.Parent as ContextMenu;
            TreeViewItem item = menu.PlacementTarget as TreeViewItem;
            ModuleProperty proWin = new ModuleProperty(item,mods);
            proWin.item = item;
            proWin.Show();
        }

        private void ExportReport_Click(object sender, RoutedEventArgs e) {
            using StreamWriter file = new StreamWriter("report.json", append: true);
            file.Write("hello");
        }
    }
}
