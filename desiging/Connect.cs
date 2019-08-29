using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Data.SqlClient;
using System.IO;
namespace desiging
{
    class Connect
    {
        public SqlConnection conn = new SqlConnection();
        public SqlCommand cmd = new SqlCommand();
        public string locate = @"Data Source=(LocalDB)\MSSQLLocalDB;AttachDbFilename='C:\Users\Talha Shafique\Desktop\desiging\desiging\userlogininfo.mdf';Integrated Security=True";
    }
    //"Data Source=(LocalDB)\MSSQLLocalDB;AttachDbFilename="+ System.IO.Path.Combine(Path.GetDirectoryName(System.Reflection.Assembly.GetEntryAssembly().Location), "UserLoginInfo.mdf") +";Integrated Security=True";
}
