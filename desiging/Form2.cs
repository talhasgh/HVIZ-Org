using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using CefSharp.WinForms;
using CefSharp;
using System.IO;

namespace desiging
{
    public partial class Form2 : Form
    {

        ChromiumWebBrowser chrome;
        string curDir = Directory.GetCurrentDirectory();
        public Form2()
        {
            InitializeComponent();
        }

        private void Form2_Load(object sender, EventArgs e)
        {
            CefSettings settings = new CefSettings();
            if (Cef.IsInitialized == true)
            {
                string Path1 = String.Format("{0}/Hviz.html", curDir);
                chrome = new ChromiumWebBrowser(Path1);
                this.Controls.Add(chrome);
                chrome.Dock = DockStyle.Fill;
                chrome.Load(Path1);
            }
            else
            {
                Cef.Initialize(settings);
                string Path2 = String.Format("{0}/Hviz.html", curDir);
                chrome = new ChromiumWebBrowser(Path2);
                this.Controls.Add(chrome);
                chrome.Dock = DockStyle.Fill;
                chrome.Load(Path2);
            }
        }
    }
}
