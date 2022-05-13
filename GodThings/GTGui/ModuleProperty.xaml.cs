using System;
using System.Collections.Generic;
using System.Text;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Shapes;

namespace GTGui
{
    /// <summary>
    /// ModuleProperty.xaml 的交互逻辑
    /// </summary>
    public partial class ModuleProperty : Window
    {
        public object Mods { get; set; }
        public object item { get; set; }
        void InitializeModuleData() {
            var modules = (List<GodAgent.Module>)this.Mods;
            var treeItem = item as TreeViewItem;
            GodAgent.Module targetModule = null;
            foreach (var module in modules) {
                if (module.Name == treeItem.Header.ToString()) {
                    targetModule = module;
                    break;
                }
            }
            if (targetModule == null) {
                return;
            }

            ModuleName.Text = targetModule.Name;
            ModulePath.Text = targetModule.Path;
            ModuleType.Text = targetModule.Type;
            ModuleClass.Text = targetModule.Class;
            ModuleDescription.Text = targetModule.Description;
        }
        public ModuleProperty(TreeViewItem item,object mods)
        {
            InitializeComponent();
            this.item = item;
            this.Mods = mods;
            InitializeModuleData();
        }
    }
}
