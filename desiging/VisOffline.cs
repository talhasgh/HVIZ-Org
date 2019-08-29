using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace desiging
{
    public partial class VisOffline : Form
    {
        Form1 frm;
        VisOffline vo;
        public VisOffline()
        {
            InitializeComponent();
            vo = new VisOffline();
            frm = new Form1();
        }

        private void VisOffline_Load(object sender, EventArgs e)
        {

        }

        private void bunifuImageButton17_Click(object sender, EventArgs e)
        {
            vo.Close();
            vo.Hide();
        }

        private void btn_offvis_Click(object sender, EventArgs e)
        {
            frm.visoffline();
        }
    }
}
