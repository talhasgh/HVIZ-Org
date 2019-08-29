using PcapDotNet.Core;
using PcapDotNet.Packets;
using PcapDotNet.Packets.Ethernet;
using PcapDotNet.Packets.Http;
using PcapDotNet.Packets.IpV4;
using PcapDotNet.Packets.Transport;
using System;
using Fiddler;
using FiddlerCore;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;
using PcapDotNet.Analysis;
using System.IO;
using System.Net.Sockets;
using System.Net;
using System.Data.SqlClient;

namespace desiging
{
    public partial class Form1 : Form
    {
        List<Image> images = new List<Image>();
        string[] location = new string[25];
        Socket clientSocket;
        private const int PORT = 9999;
        private byte[] buf = new byte[8024];
        Thread th;
        string remoteip = "";
        string datetime = "";
        IPEndPoint Ip;
        Mutex mutex;
        int scounter, ncounter, pb;
        List<URLClass> URLData;
        PacketCommunicator communicator;
        static int count = 0;
        URLClass urlData;
        PacketDevice device;
        int index = 0;
        private bool first_time = true;
        private IList<LivePacketDevice> AdaptersList;
        List<HeadRequestClass> rHead;
        List<URLClass> rClick;
        List<URLClass> rEmb;
        List<URLClass> Mal;
        Thread tah;
        Thread malTh;
        PacketDevice selectedAdapter;
        string pktcont = "";
        string time = "";
        string source = "";
        string httpver = "";
        string reqmethod = "";
        string reqconnection = "";
        string requrl = "";
        string requrlref = "";
        string reqtype = "";
        string reqcookies = "";
        string reqagent = "";
        string httphead = "";
        Thread mythread;
        private Socket sock = new Socket(System.Net.Sockets.AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        HeadRequestClass hrc;
        VisOffline vo;
        int counter = 0;
        bool multi;
        int jcounter = 0;

        List<URLClass> urlclass;

        string[] names;

        public Form1()
        {
            InitializeComponent();
            location[0] = @"C:\Users\Talha Shafique\Desktop\desiging\desiging\bin\x64\Debug\animation\textbox_user_1.jpg";
            location[1] = @"C:\Users\Talha Shafique\Desktop\desiging\desiging\bin\x64\Debug\animation\textbox_user_2.jpg";
            location[2] = @"C:\Users\Talha Shafique\Desktop\desiging\desiging\bin\x64\Debug\animation\textbox_user_4.jpg";
            location[3] = @"C:\Users\Talha Shafique\Desktop\desiging\desiging\bin\x64\Debug\animation\textbox_user_5.jpg";
            location[4] = @"C:\Users\Talha Shafique\Desktop\desiging\desiging\bin\x64\Debug\animation\textbox_user_6.jpg";
            location[5] = @"C:\Users\Talha Shafique\Desktop\desiging\desiging\bin\x64\Debug\animation\textbox_user_7.jpg";
            location[6] = @"C:\Users\Talha Shafique\Desktop\desiging\desiging\bin\x64\Debug\animation\textbox_user_8.jpg";
            location[7] = @"C:\Users\Talha Shafique\Desktop\desiging\desiging\bin\x64\Debug\animation\textbox_user_9.jpg";
            location[8] = @"C:\Users\Talha Shafique\Desktop\desiging\desiging\bin\x64\Debug\animation\textbox_user_10.jpg";
            location[9] = @"C:\Users\Talha Shafique\Desktop\desiging\desiging\bin\x64\Debug\animation\textbox_user_11.jpg";
            location[10] = @"C:\Users\Talha Shafique\Desktop\desiging\desiging\bin\x64\Debug\animation\textbox_user_12.jpg";
            location[11] = @"C:\Users\Talha Shafique\Desktop\desiging\desiging\bin\x64\Debug\animation\textbox_user_13.jpg";
            location[12] = @"C:\Users\Talha Shafique\Desktop\desiging\desiging\bin\x64\Debug\animation\textbox_user_14.jpg";
            location[13] = @"C:\Users\Talha Shafique\Desktop\desiging\desiging\bin\x64\Debug\animation\textbox_user_15.jpg";
            location[14] = @"C:\Users\Talha Shafique\Desktop\desiging\desiging\bin\x64\Debug\animation\textbox_user_16.jpg";
            location[15] = @"C:\Users\Talha Shafique\Desktop\desiging\desiging\bin\x64\Debug\animation\textbox_user_17.jpg";
            location[16] = @"C:\Users\Talha Shafique\Desktop\desiging\desiging\bin\x64\Debug\animation\textbox_user_18.jpg";
            location[17] = @"C:\Users\Talha Shafique\Desktop\desiging\desiging\bin\x64\Debug\animation\textbox_user_19.jpg";
            location[18] = @"C:\Users\Talha Shafique\Desktop\desiging\desiging\bin\x64\Debug\animation\textbox_user_20.jpg";
            location[19] = @"C:\Users\Talha Shafique\Desktop\desiging\desiging\bin\x64\Debug\animation\textbox_user_21.jpg";
            location[20] = @"C:\Users\Talha Shafique\Desktop\desiging\desiging\bin\x64\Debug\animation\textbox_user_22.jpg";
            location[21] = @"C:\Users\Talha Shafique\Desktop\desiging\desiging\bin\x64\Debug\animation\textbox_user_23.jpg";
            location[22] = @"C:\Users\Talha Shafique\Desktop\desiging\desiging\bin\x64\Debug\animation\textbox_user_24.jpg";
            tounage();
            mutex = new Mutex();
            urlData = new URLClass();
            URLData = new List<URLClass>();
            rHead = new List<HeadRequestClass>();
            rClick = new List<URLClass>();
            rEmb = new List<URLClass>();
            urlclass = new List<URLClass>();
            Mal = new List<URLClass>();
            vo = new VisOffline();
            try
            {
                AdaptersList = LivePacketDevice.AllLocalMachine;//locate all adapters
            }
            catch (Exception e)
            {
                MessageBox.Show("Please make sure to run as Adminstrator and install Winpcap");
            }

            PcapDotNetAnalysis.OptIn = true;//enable pcap analysis

            if (AdaptersList.Count == 0)
            {

                MessageBox.Show("No adapters found !!");

                return;

            }

            for (int i = 0; i != AdaptersList.Count; ++i)//add all adapters to my Combobox
            {
                LivePacketDevice Adapter = AdaptersList[i];

                if (Adapter.Description != null)

                    adapters_list.Items.Add(Adapter.Description);
                else
                    adapters_list.Items.Add("Unknown");
            }
        }

        private void flowLayoutPanel1_Paint(object sender, PaintEventArgs e)
        {

        }

        private void panel1_Paint(object sender, PaintEventArgs e)
        {

        }

        private void pictureBox2_Click(object sender, EventArgs e)
        {

            Application.Exit();


        }
       

        private void panel3_Paint(object sender, PaintEventArgs e)
        {

        }

        private void bunifuImageButton1_Click(object sender, EventArgs e)
        {
            MessageBox.Show("");
        }

        private void btn_home_Click(object sender, EventArgs e)
        {
            panel_online.SendToBack();
            panel_offline.SendToBack();
            panel_aboutus.SendToBack();
            panel_home.BringToFront();


        }

        private void btn_about_Click(object sender, EventArgs e)
        {


            panel_aboutus.BringToFront();
            panel_aboutus.Show();
            panel_aboutus.Visible = true;
        }

        private void bunifuFlatButton2_Click(object sender, EventArgs e)
        {
            OpfileWork();

        }

        private async void OpfileWork()
        {
            OpenFileDialog ofd = new OpenFileDialog();
            ofd.InitialDirectory = "c:\\";
            ofd.Filter = "Wireshark capture file (*.pcap)|*.pcap|All files (*.*)|*.*";

            if (ofd.ShowDialog() == DialogResult.OK)
            {
                btn_offclear.Enabled = true;
                label3.Invoke(new Action(() => { label3.Text = "Loading file on software please wait"; }));

                try
                {

                    //groupBox1.Enabled = true;
                    Task task = new Task(() => startReadCapture(ofd.FileName));
                    task.Start();
                    await task;
                }
                catch (Exception ex)
                {
                    MessageBox.Show(ex.Message);
                }
            }
            offlinework();
        }
        private void tounage()
        {
            //for (int i = 0; i < 23; i++)
            //{
            //    Bitmap bitmap = new Bitmap(location[i]);
            //    images.Add(bitmap);
            //}
            //images.Add(Properties.Resources.textbox_user_24);
        }

        private void offlinework()
        {
            foreach (var a in URLData)
            {
                if (!count.Equals(""))
                {
                    ListViewItem item = new ListViewItem(a.PktCount.ToString());
                    item.SubItems.Add(Convert.ToString(a.PktTime));
                    item.SubItems.Add(a.SourceIP);
                    item.SubItems.Add(a.HttpMethod);
                    item.SubItems.Add(a.ConnectionType);
                    item.SubItems.Add(a.HttpVersion);
                    item.SubItems.Add(a.URLString);
                    item.SubItems.Add(a.URLReferer);
                    item.SubItems.Add(a.ContentType);
                    item.SubItems.Add(a.HttpCookie);
                    item.SubItems.Add(a.UserAgent);

                    ListV_live.Invoke(new Action(() => ListV_live.Items.Insert(0, item)));
                }

            }
            label3.Invoke(new Action(() => { label3.Text = "File loaded successfully"; }));
        }

        private void startReadCapture(string fileName)
        {
            OfflinePacketDevice selectedDevice = new OfflinePacketDevice(fileName);

            CapturePackets(selectedDevice);
        }

        private void CapturePackets(OfflinePacketDevice selectedDevice)
        {
            try
            {
                GC.Collect();
                using (communicator = selectedDevice.Open(65536, PacketDeviceOpenAttributes.Promiscuous, 1000))                                  // read timeout
                {
                    // Check the link layer. We support only Ethernet for simplicity.
                    if (communicator.DataLink.Kind != DataLinkKind.Ethernet)
                    {
                        Console.WriteLine("This program works only on Ethernet networks.");
                        return;
                    }

                    communicator.ReceivePackets(0, PacketHandler);
                }




            }

            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
            }

            communicator.ReceivePackets(0, PacketHandler);

        }





        private void PacketHandler(Packet packet)
        {
            try
            {
                ++count;


                if (packet.DataLink.Kind == DataLinkKind.Ethernet)
                {
                    EthernetDatagram ethernet = packet.Ethernet;
                    if (ethernet.EtherType == EthernetType.IpV4)
                    {
                        IpV4Datagram ip = packet.Ethernet.IpV4;
                        if (ip.Protocol == IpV4Protocol.Tcp)
                        {
                            TcpDatagram tcp = ip.Tcp;

                            if (packet.Ethernet.IpV4.Tcp.Http != null)
                            {

                                HttpDatagram http = packet.Ethernet.IpV4.Tcp.Http;


                                if (http != null && http.Header != null && http.IsRequest)
                                {
                                    PcapDotNet.Packets.Http.HttpRequestDatagram http2 = (HttpRequestDatagram)packet.Ethernet.IpV4.Tcp.Http;

                                    URLClass urlclass = new URLClass();



                                    //Console.WriteLine("Packet Count: " + count.ToString());
                                    urlclass.PktCount = count;

                                    //Console.WriteLine("Source IP: " + ip.Source.ToString());
                                    urlclass.SourceIP = ip.Source.ToString();

                                    //Console.WriteLine("Time: " + packet.Timestamp.ToString());
                                    urlclass.PktTime = packet.Timestamp;
                                    //Console.WriteLine("HTTP packet length: " + http.Length.ToString());

                                    //Console.WriteLine("HTTP Method: " + http2.Method.Method); 
                                    urlclass.HttpMethod = http2.Method.Method.ToString();

                                    //Console.WriteLine("HTTP Version: " + http2.Version);
                                    urlclass.HttpVersion = http2.Version.ToString(); ;


                                    string[] qas = http.Header.ToString().Split(new char[] { '\r', '\n' });

                                    foreach (var q in qas)
                                    {
                                        if (q.StartsWith("Referer"))
                                        {
                                            urlclass.URLReferer = q;
                                            //Console.WriteLine(q);
                                        }
                                        else if (q.StartsWith("User-Agent"))
                                        {
                                            urlclass.UserAgent = q;
                                            //Console.WriteLine(q);
                                        }
                                        else if (q.StartsWith("Accept:"))
                                        {
                                            urlclass.ContentType = q;
                                            //Console.WriteLine(q);
                                        }
                                        else if (q.StartsWith("Cookie"))
                                        {
                                            urlclass.HttpCookie = q;
                                            //Console.WriteLine(q);
                                        }
                                        else if (q.StartsWith("Connection"))
                                        {
                                            urlclass.ConnectionType = q;
                                            //Console.WriteLine(q);
                                        }
                                        else if (q.StartsWith("Host"))
                                        {
                                            string[] hostString = q.Split(':');

                                            urlclass.URLString = hostString[1] + http2.Uri;
                                            //Console.WriteLine("URL: " + urlclass.URLString);
                                        }
                                        else if (q.StartsWith("X-Requested-With"))
                                        {
                                            Console.WriteLine(q);
                                        }

                                    }
                                    if (urlclass.ContentType == null)
                                        urlclass.ContentType = "-";

                                    URLData.Add(urlclass);


                                }
                            }

                        }

                    }
                }

            }
            catch (Exception ex)
            {
                MessageBox.Show(ex.Message);
            }
        }

        private void btn_new_Click(object sender, EventArgs e)
        {

            label3.Text = "...";
            OpfileWork();
        }

        private void bunifuFlatButton1_Click(object sender, EventArgs e)
        {

            label3.Text = "...";
            ListV_live.Items.Clear();
        }

        private void panel8_Paint(object sender, PaintEventArgs e)
        {

        }

        private void Form1_Load(object sender, EventArgs e)
        {
           
            btn_MalClear.Enabled = false;
            timer1.Start();
            signup_pnl.Visible = false;
            sock.Bind(new IPEndPoint(IPAddress.Any, PORT));
            sock.Listen(500);
            //th = new Thread(Accept);
            //th.Start();
            btn_Server.Enabled = false;
            saveToolStripMenuItem.Enabled = false;
            stopHTTPRequestsToolStripMenuItem.Enabled = false;
            stopHVIZToolStripMenuItem.Enabled = false;
            stopHTTPSCapturingToolStripMenuItem.Enabled = false;
            stopToolStripMenuItem.Enabled = false;
            pnl_server.Dock = pnl_login.Dock = panel_online.Dock = panel_offline.Dock = panel_home.Dock = panel_aboutus.Dock = DockStyle.Fill;
            pnl_server.Parent = pnl_login.Parent = panel_online.Parent = panel_offline.Parent = panel_home.Parent = panel_aboutus.Parent = this;
            btn_save.Enabled = false;
            btn_stop.Enabled = false;
            btn_vislive.Enabled = false;
            btn_offclear.Enabled = false;
            btn_offvis.Enabled = false;
            adapters_list.Visible = false;
            lbl_adap.Visible = false;
            visualizeDataToolStripMenuItem.Enabled = false;
            Btn_serGolive.Enabled = true;
            btn_Stoplisten.Enabled = false;
            button1.Enabled = false;
            button2.Enabled = false;
        }
        

        private void btn_stop_Click(object sender, EventArgs e)
        {
            stoplivecapt();
        }

        private void stoplivecapt()
        {
            UinstallCert();
            stopingliveCap();
        }

        private void stopingliveCap()
        {
            startToolStripMenuItem.Enabled = true;
            stopToolStripMenuItem.Enabled = false;
            btn_stop.Enabled = false;
            btn_capture.Enabled = true;
            FiddlerApplication.AfterSessionComplete -= FiddlerApplication_AfterSessionComplete;

            if (FiddlerApplication.IsStarted())
                FiddlerApplication.Shutdown();
        }

        private static bool UinstallCert()
        {
            if (CertMaker.rootCertExists())
            {
                if (!CertMaker.removeFiddlerGeneratedCerts(true))
                    return false;
            }
            return true;
        }

        private void btn_capture_Click(object sender, EventArgs e)
        {
            OnlineCap();
        }

        private void OnlineCap()
        {
            Certificateinstall();
            livecap();
        }

        private void livecap()
        {
            stopToolStripMenuItem.Enabled = true;
            saveToolStripMenuItem.Enabled = true;
            captureBothHTTPHTTPSToolStripMenuItem.Enabled = false;
            stopHVIZToolStripMenuItem.Enabled = true;
            startToolStripMenuItem.Enabled = false;
            btn_save.Enabled = true;
            btn_stop.Enabled = true;
            btn_capture.Enabled = false;
            FiddlerApplication.AfterSessionComplete += FiddlerApplication_AfterSessionComplete;
            FiddlerApplication.Startup(8888, true, true, true);

        }

        private void FiddlerApplication_AfterSessionComplete(Session sess)
        {
            this.time = ""; this.source = ""; this.httpver = ""; this.reqmethod = "";
            this.reqconnection = "";
            this.requrl = "";
            this.requrlref = "";
            this.reqtype = "";
            this.reqcookies = "";
            this.reqagent = ""; this.pktcont = "";
            if (sess == null || sess.oRequest == null || sess.oRequest.headers == null)
                return;

            if (sess.RequestMethod.Contains("GET") || sess.RequestMethod.Contains("POST"))
            {


                string headers = sess.oRequest.headers.ToString();
                var reqBody = Encoding.UTF8.GetString(sess.RequestBody);
                string url = sess.fullUrl.ToLower();
                URLClass urlclass = new URLClass();
                pktcont = sess.id.ToString();
                time = sess.Timers.ClientBeginRequest.ToString();
                source = sess.m_clientIP;
                reqmethod = sess.RequestMethod;
                httpver = sess.oRequest.headers.HTTPVersion;
                requrl = sess.url;
                //if (sess.isHTTPS)
                //{
                //    string https = "https://";
                //    requrl = https + sess.url;
                //}
                //else
                //{
                //    string https = "http://";
                //    requrl = https + sess.url;
                //}

                string[] qas = headers.ToString().Split(new char[] { '\r', '\n' });

                foreach (var q in qas)
                {
                    if (q.StartsWith("Referer"))
                    {
                        requrlref = q;

                    }
                    if (q.StartsWith("User-Agent"))
                    {
                        reqagent = q;

                    }
                    else if (q.StartsWith("Connection"))
                    {
                        reqconnection = q;

                    }
                    else if (q.StartsWith("Cookie"))
                    {
                        reqcookies = q;

                    }
                    else if (q.StartsWith("Accept:"))
                    {
                        reqtype = q;

                    }

                }

                URLData.Add(urlclass);

                livelistview();
            }
        }

        private void livelistview()
        {
            if (!count.Equals("") && listView1 != null)
            {

                ListViewItem item = new ListViewItem(pktcont);
                item.SubItems.Add(Convert.ToString(time));
                item.SubItems.Add(source);
                item.SubItems.Add(reqmethod);
                item.SubItems.Add(reqconnection);
                item.SubItems.Add(httpver);
                item.SubItems.Add(requrl);
                item.SubItems.Add(requrlref);
                item.SubItems.Add(reqtype);
                item.SubItems.Add(reqcookies);
                item.SubItems.Add(reqagent);
                listView1.Invoke(new Action(() => listView1.Items.Insert(0, item)));

            }
        }

        private static bool Certificateinstall()
        {
            if (!CertMaker.rootCertExists())
            {
                if (!CertMaker.createRootCert())
                    return false;

                if (!CertMaker.trustRootCert())
                    return false;


            }

            return true;
        }

        private void btn_offlineR_Click(object sender, EventArgs e)
        {
            panel_online.SendToBack();
            panel_home.SendToBack();
            panel_aboutus.SendToBack();
            panel_offline.BringToFront();
        }

        private void btn_onlineC_Click(object sender, EventArgs e)
        {
            panel_offline.SendToBack();
            panel_home.SendToBack();
            panel_aboutus.SendToBack();
            panel_online.BringToFront();
            names = Directory.GetFiles(Environment.CurrentDirectory, "*.log").Select(file => Path.GetFileNameWithoutExtension(file)).ToArray();
            for (int i = 0; i < names.Count(); i++)
            {
                cbIPS1.Items.Add(names[i]);
            }
        }

        private void pictureBox3_Click(object sender, EventArgs e)
        {
            this.WindowState = FormWindowState.Minimized;
        }

        private void installingCertificateToolStripMenuItem_Click(object sender, EventArgs e)
        {

        }

        private void startToolStripMenuItem_Click(object sender, EventArgs e)
        {
            OnlineCap();
        }

        private void stopToolStripMenuItem_Click(object sender, EventArgs e)
        {
            stoplivecapt();
        }

        private void exitToolStripMenuItem_Click(object sender, EventArgs e)
        {
            Application.Exit();
        }
        private async void Blink()
        {
            while (true)
            {
                await Task.Delay(500);
                label4.BackColor = label4.BackColor == Color.Green ? Color.Aqua : Color.Green;
            }
        }
        private void captureHTTPOnlyToolStripMenuItem_Click(object sender, EventArgs e)
        {
            stopHTTPRequestsToolStripMenuItem.Enabled = true;
            captureHTTPOnlyToolStripMenuItem.Enabled = false;
            btn_capture.Enabled = false;
            Blink();
            label4.Show();
            adapters_list.Visible = true;
            lbl_adap.Visible = true;
            livehttpCap();
        }

        private void livehttpCap()
        {
            if (adapters_list.Enabled == true && adapters_list.SelectedIndex >= 0)
            {
                selectedAdapter = AdaptersList[adapters_list.SelectedIndex];
                Thread mythread = new Thread(new System.Threading.ThreadStart(NewWork));
                mythread.Start();
            }
            else
            {
                MessageBox.Show("Please select adapter to continue", "Adapter Error", MessageBoxButtons.OK,
                MessageBoxIcon.Information);
            }
        }
        private void NewWork()
        {
            using (PacketCommunicator communicator = selectedAdapter.Open(65536, PacketDeviceOpenAttributes.Promiscuous, 1000))
            {
                try
                {

                    // Check the link layer. We support only Ethernet for simplicity.
                    if (communicator.DataLink.Kind != DataLinkKind.Ethernet)
                    {
                        Console.WriteLine("This program works only on Ethernet networks.");
                        return;
                    }


                    communicator.ReceivePackets(0, PacketHandlera);




                }
                catch (Exception ex) { Console.WriteLine(ex.Message); }



                communicator.ReceivePackets(0, PacketHandlera);




            }
        }

        private void PacketHandlera(Packet packet)
        {
            this.time = ""; this.source = ""; this.httpver = ""; this.reqmethod = "";
            this.reqconnection = "";
            this.requrl = "";
            this.requrlref = "";
            this.reqtype = "";
            this.reqcookies = "";
            this.reqagent = ""; this.pktcont = "";
            if (packet.DataLink.Kind == DataLinkKind.Ethernet)
            {
                EthernetDatagram ethernet = packet.Ethernet;
                if (ethernet.EtherType == EthernetType.IpV4)
                {
                    IpV4Datagram ip = packet.Ethernet.IpV4;
                    if (ip.Protocol == IpV4Protocol.Tcp)
                    {
                        TcpDatagram tcp = ip.Tcp;

                        if (packet.Ethernet.IpV4.Tcp.Http != null)
                        {

                            HttpDatagram http = packet.Ethernet.IpV4.Tcp.Http;


                            // if http is 
                            if (http != null && http.Header != null && http.IsRequest)
                            {
                                PcapDotNet.Packets.Http.HttpRequestDatagram http2 = (HttpRequestDatagram)packet.Ethernet.IpV4.Tcp.Http;

                                {
                                    pktcont = packet.Count.ToString();


                                }
                                {
                                    time = packet.Timestamp.ToString();

                                }
                                {
                                    source = ip.Source.ToString();

                                }

                                {
                                    httpver = http.Version.ToString();

                                }
                                {
                                    reqmethod = http2.Method.Method.ToString();

                                }

                                httphead = http.Header.ToString();
                                string[] dat = http.Header.ToString().Split(new char[] { '\r', '\n' });
                                foreach (var a in dat)
                                {
                                    if (a.StartsWith("Referer"))
                                    {
                                        requrlref = a;

                                    }
                                    else if (a.StartsWith("User-Agent"))
                                    {
                                        reqagent = a;


                                    }
                                    else if (a.StartsWith("Accept:"))
                                    {
                                        reqtype = a;

                                    }
                                    else if (a.StartsWith("Cookie"))
                                    {
                                        reqcookies = a;

                                    }
                                    else if (a.StartsWith("Connection"))
                                    {
                                        reqconnection = a;
                                    }
                                    else if (a.StartsWith("Host"))
                                    {
                                        string[] hostString = a.Split(':');

                                        requrl = hostString[1] + http2.Uri;


                                    }



                                }
                                startwork();

                            }
                        }
                    }
                }
            }
        }

        private void startwork()
        {
            if (!count.Equals(""))
            {

                ListViewItem item = new ListViewItem(pktcont);
                item.SubItems.Add(Convert.ToString(time));
                item.SubItems.Add(source);
                item.SubItems.Add(reqmethod);
                item.SubItems.Add(reqconnection);
                item.SubItems.Add(httpver);
                item.SubItems.Add(requrl);
                item.SubItems.Add(requrlref);
                item.SubItems.Add(reqtype);
                item.SubItems.Add(reqcookies);
                item.SubItems.Add(reqagent);
                listView1.Invoke(new Action(() => listView1.Items.Insert(0, item)));

            }
        }

        private void captureHTTPSOnlyToolStripMenuItem_Click(object sender, EventArgs e)
        {
            Certificateinstall();
            stopHTTPSCapturingToolStripMenuItem.Enabled = true;
            captureHTTPOnlyToolStripMenuItem.Enabled = false;
            FiddlerApplication.AfterSessionComplete += FiddlerApplication_AfterSessionComplete2;
            FiddlerApplication.Startup(8888, true, true, true);

        }

        private void FiddlerApplication_AfterSessionComplete2(Session sess)
        {
            this.time = ""; this.source = ""; this.httpver = ""; this.reqmethod = "";
            this.reqconnection = "";
            this.requrl = "";
            this.requrlref = "";
            this.reqtype = "";
            this.reqcookies = "";
            this.reqagent = ""; this.pktcont = "";
            if (sess == null || sess.oRequest == null || sess.oRequest.headers == null)
                return;
            if (sess.isHTTPS)
            {
                if (sess.RequestMethod.Contains("GET") || sess.RequestMethod.Contains("POST"))
                {


                    string headers = sess.oRequest.headers.ToString();
                    var reqBody = Encoding.UTF8.GetString(sess.RequestBody);
                    string url = sess.fullUrl.ToLower();
                    URLClass urlclass = new URLClass();
                    pktcont = sess.id.ToString();
                    time = sess.Timers.ToString();
                    source = sess.m_clientIP;
                    reqmethod = sess.RequestMethod;
                    httpver = sess.oRequest.headers.HTTPVersion;

                    string[] qas = headers.ToString().Split(new char[] { '\r', '\n' });

                    foreach (var q in qas)
                    {
                        if (q.StartsWith("Referer"))
                        {
                            requrlref = q;

                        }
                        else if (q.StartsWith("User-Agent"))
                        {
                            reqagent = q;

                        }
                        else if (q.StartsWith("Connection"))
                        {
                            reqconnection = q;

                        }
                        else if (q.StartsWith("Cookie"))
                        {
                            reqcookies = q;

                        }
                        else if (q.StartsWith("Accept:"))
                        {
                            reqtype = q;

                        }
                        else if (q.StartsWith("Host"))
                        {
                            requrl = q;
                        }
                    }

                    URLData.Add(urlclass);
                }
                livelistview();
            }
        }

        private void stopHTTPSCapturingToolStripMenuItem_Click(object sender, EventArgs e)
        {
            UinstallCert();
            captureHTTPSOnlyToolStripMenuItem.Enabled = true;
            stopHTTPSCapturingToolStripMenuItem.Enabled = false;
            stopingliveCap();
        }

        private void captureBothHTTPHTTPSToolStripMenuItem_Click(object sender, EventArgs e)
        {
            OnlineCap();
        }

        private void stopHVIZToolStripMenuItem_Click(object sender, EventArgs e)
        {
            UinstallCert();
            stopingliveCap();
        }

        private void stopHTTPRequestsToolStripMenuItem_Click(object sender, EventArgs e)
        {
            stopHVIZToolStripMenuItem.Enabled = false;
            btn_capture.Enabled = true;

            captureHTTPOnlyToolStripMenuItem.Enabled = true;
            stopHTTPRequestsToolStripMenuItem.Enabled = false;
            lbl_adap.Hide();
            adapters_list.Hide();
            label4.Hide();

            if (listView1.Items == null)
            {
                mythread.Abort();
            }
            else
            {
                MessageBox.Show("No file captured", "Capturing Error", MessageBoxButtons.OKCancel);
            }
        }

        private void captureToolStripMenuItem1_Click(object sender, EventArgs e)
        {

        }

        private void fileToolStripMenuItem1_Click(object sender, EventArgs e)
        {

        }

        private void newToolStripMenuItem_Click(object sender, EventArgs e)
        {
            listvliveitem();
            OpfileWork();
        }

        private void openToolStripMenuItem_Click(object sender, EventArgs e)
        {

            //listvliveitem();
            OpfileWork();
        }

        private void listvliveitem()
        {
            if (ListV_live.Items != null)
            {
                ListV_live.Items.Clear();
            }
            else
            {
                return;
            }
        }

        private void exitToolStripMenuItem1_Click(object sender, EventArgs e)
        {
            Application.Exit();
        }

        private void aboutUsToolStripMenuItem_Click(object sender, EventArgs e)
        {
            panel_home.Hide();

            panel_aboutus.Show();
            panel_aboutus.BringToFront();
        }

        private void aboutHVIZToolStripMenuItem_Click(object sender, EventArgs e)
        {
            panel_home.Show();
            panel_home.BringToFront();
        }

        private void versionToolStripMenuItem1_Click(object sender, EventArgs e)
        {
            MessageBox.Show("Version 2.0.1",
               "Application Version", MessageBoxButtons.OK,
               MessageBoxIcon.Information);
        }

        private void usageToolStripMenuItem1_Click(object sender, EventArgs e)
        {
            MessageBox.Show("Use any dump file with extension .pcap to read every single packet in it. In live capture mode, Application will start listening to your network traffic. Certificate are basically used for HTTPS as we're using intercepting proxy server to capture secure packets",
                "Application Usage", MessageBoxButtons.OK,
                MessageBoxIcon.Information);
        }

        private void loginToolStripMenuItem_Click(object sender, EventArgs e)
        {
            MessageBox.Show("Login is required if you want to analyze and visualize the traffic for security reasons. Click Login tab to make your login or contact Developers in about us tab.",
                "Application Login", MessageBoxButtons.OK,
                MessageBoxIcon.Information);
        }

        private void rateUsToolStripMenuItem_Click(object sender, EventArgs e)
        {

        }

        private void btn_save_Click(object sender, EventArgs e)
        {
            if (listView1.Items == null)
            {
                MessageBox.Show("Capture some data to before saving", "Error saving file", MessageBoxButtons.OK,
               MessageBoxIcon.Information);
            }
            else
            {
                savefilework();
            }
        }

        private void savefilework()
        {
            string filename = "";
            SaveFileDialog sfd = new SaveFileDialog();

            sfd.Title = "Saving Captured Traffic";
            sfd.Filter = "HVIZ LOG FILE (*.log) | *.log| HVIZ Text file (*.txt) | *.txt";

            if (sfd.ShowDialog() == DialogResult.OK)
            {
                filename = sfd.FileName.ToString();
                if (filename != "")
                {
                    //string path = @"C:\Users\Talha Shafique\Desktop";
                    //if (!File.Exists(path))
                    //{
                    //    using (StreamWriter a = File.CreateText(path))

                    using (StreamWriter sw = new StreamWriter(filename))
                    {

                        for (int i = 0; i < listView1.Items.Count; ++i)
                        {
                            sw.WriteLine("{0}{1}{2}{3}{4}{5}{6}{7}{8}", listView1.Items[i].SubItems[1].Text, "|", listView1.Items[i].SubItems[3].Text, "|", listView1.Items[i].SubItems[6].Text, "|", listView1.Items[i].SubItems[7].Text, "|", listView1.Items[i].SubItems[8].Text);
                        }
                    }

                }
            }
        }

        private void saveToolStripMenuItem_Click(object sender, EventArgs e)
        {
            if (listView1.Items == null)
            {
                MessageBox.Show("Capture some data to before saving", "Error saving file", MessageBoxButtons.OK,
               MessageBoxIcon.Information);
            }
            else
            {
                savefilework();
            }
        }

        private void saveToolStripMenuItem1_Click(object sender, EventArgs e)
        {
            if (listView1.Items == null)
            {
                MessageBox.Show("Capture some data to before saving", "Error saving file", MessageBoxButtons.OK,
               MessageBoxIcon.Information);
            }
            else
            {
                savefilework();
            }
        }

        private void btn_login_Click(object sender, EventArgs e)
        {
            pnl_login.BringToFront();
            pnl_login.Show();
            pnl_login.Visible = true;
        }

        private void textBox1_TextChanged(object sender, EventArgs e)
        {
            if (tb_loginUN.Text.Length > 0 && tb_loginUN.Text.Length <= 15)
            {
                pictureBox11.Image = images[tb_loginUN.Text.Length - 1];
                pictureBox11.BackgroundImageLayout = ImageLayout.Stretch;
            }
            else if (tb_loginUN.Text.Length <= 0)
                pictureBox11.Image = Properties.Resources.debut;
            else
                pictureBox11.Image = images[22];
        }

        private void textBox1_Click(object sender, EventArgs e)
        {
            if (tb_loginUN.Text.Length > 0)
                pictureBox11.Image = images[tb_loginUN.Text.Length - 1];
            else
                pictureBox11.Image = Properties.Resources.debut;
        }

        private void textBox2_TextChanged(object sender, EventArgs e)
        {
            EyeshideImage();
        }

        private void textBox2_Click(object sender, EventArgs e)
        {
            EyeshideImage();
        }
        private void EyeshideImage()
        {
            Bitmap bmpass = new Bitmap(@"C:\Users\Talha Shafique\Desktop\desiging\desiging\bin\x64\Debug\animation\textbox_password.png");
            pictureBox11.Image = bmpass;
        }

        private void textBox1_TextChanged_1(object sender, EventArgs e)
        {
            if (tb_loginUN.Text.Length > 0 && tb_loginUN.Text.Length <= 15)
            {
                pictureBox11.Image = images[tb_loginUN.Text.Length - 1];
                pictureBox11.BackgroundImageLayout = ImageLayout.Stretch;
            }
            else if (tb_loginUN.Text.Length <= 0)
                pictureBox11.Image = Properties.Resources.debut;
            else
                pictureBox11.Image = images[22];
        }


        private void textBox1_Click_1(object sender, EventArgs e)
        {

            if (tb_loginUN.Text.Length > 0)
                pictureBox11.Image = images[tb_loginUN.Text.Length - 1];
            else
                pictureBox11.Image = Properties.Resources.debut;
        }

        private void textBox2_TextChanged_1(object sender, EventArgs e)
        {
            EyeshideImage();
        }

        private void textBox2_Click_1(object sender, EventArgs e)
        {
            EyeshideImage();
        }

        private void btn_vislive_Click(object sender, EventArgs e)
        {
            visbuttonwork();
        }

        private void visbuttonwork()
        {
            rHead = new List<HeadRequestClass>();
            string[] files = Directory.GetFiles(Environment.CurrentDirectory, "" + cbIPS1.Text + ".mal");
            this.Refresh();
            //names = Directory.GetFiles(Environment.CurrentDirectory,"*.log").Select(file => Path.GetFileNameWithoutExtension(file)).ToArray();
            //foreach (string a in files)
            //{
            //    names = (Path.GetFileName(a)).ToArray();
            //}
            //this.Refresh();
            scounter = files.Count();
            ncounter = 0;
            pb = files.Length;
            int current = 0;
            // pbViz.Value = 0;
            foreach (string file in files)
            {

                string temp = "";
                StreamReader sr = new StreamReader(file);
                while (sr.Peek() > 0)
                {
                    temp = sr.ReadLine().Trim();

                    URLClass urlData = new URLClass();
                    if (temp.Length > 0)
                    {
                        string[] data = temp.ToString().Split('|');

                        //urlData.PktTime = Convert.ToDateTime(data[0]);
                        if (data[0] == "" || data != null)
                        {
                            urlData.PktTime = DateTime.Now;
                        }
                        else
                        {
                            if (data[0] != "" || data != null)
                            {
                                urlData.PktTime = Convert.ToDateTime(data[0]);
                            }
                        }
                        urlData.HttpMethod = data[1];
                        urlData.URLString = data[2];
                        foreach (var dat in data)
                        {
                            if (dat.StartsWith("Referer:"))
                            {
                                urlData.URLReferer = dat;

                            }


                            if (dat.StartsWith("Accept:"))
                            {
                                urlData.ContentType = dat;

                            }
                            else
                            {
                                urlData.ContentType = "";
                            }
                        }
                        if (urlData.URLReferer == null)
                        {
                            urlData.URLReferer = "";
                        }
                        //urlData.URLReferer = data[3];
                        //urlData.ContentType = Convert.ToString(data[4]);


                        //check urlData.UrlString is malicious or not
                       // Thread malth = new Thread();
                        urlData.IsMalicious = CheckMalicious(urlData.URLString);
                        if (urlData.IsMalicious)
                        {
                            //MessageBox.Show(urlData.URLString);
                            //rtb_malact.AppendText( "Malicious Request :" + urlData.URLString);
                            rtb_malact.Invoke((MethodInvoker)(() => rtb_malact.AppendText ( "Malicious Request :" + urlData.URLString+"\n")));
                           
                            Mal.Add(urlData);
                            
                        }
                        urlclass.Add(urlData);
                        
                    }
                }

                foreach (var x in urlclass)
                {

                    HeadRequestClass hrc = new HeadRequestClass();
                    
                    // for head requests
                    if ((x.URLReferer == null || x.URLReferer == "") || (x.ContentType.Contains("text/html")) || x.ContentType.Contains("text/xhtml"))
                    {

                        hrc.ReqType = "Head Request";
                        hrc.UrlData = x;
                        rHead.Add(hrc);
                    }
                    // for click requests
                    else if ((x.URLReferer != null || x.URLReferer != "") && (x.ContentType.Contains("text/html") || x.ContentType.Contains("text/xhtml")))
                    {
                        hrc.ReqType = "Click Stream Request";
                        hrc.UrlData = x;
                        rHead.Add(hrc);

                        for (int i = rHead.Count - 2; i > -1; --i)
                        {
                            if (x.URLReferer.EndsWith(rHead[i].UrlData.URLString.Trim()))
                            {
                                rHead[i].ClickStreamIndex.Add(rHead.Count - 1);
                                break;
                            }
                            
                        }
                    }

                    // for embedded requests
                    else
                    {
                        hrc.ReqType = "Embedded Request";
                        hrc.UrlData = x;
                        rHead.Add(hrc);
                        {
                            for (int i = rHead.Count - 2; i > -1; --i)
                            {
                                if (x.URLReferer.EndsWith(rHead[i].UrlData.URLString.Trim()))
                                {
                                    rHead[i].EmbeddedStream.Add(rHead.Count - 1);
                                    break;
                                }
                            }
                        }

                    }
                }
                //MessageBox.Show("sad");

                //for (int i = 0; i < rHead.Count; i++)
                //{
                //    if (rHead[i].ReqType == "Head Request")
                //    {
                //        MessageBox.Show(i.ToString());
                //    }

                //}

                //foreach (var s in rHead)
                //{
                //    if (s.ReqType == "Head Request")
                //    {

                //        foreach (var ss in s.ClickStreamIndex)
                //            MessageBox.Show(ss.ToString(), "Click Stream Request No");

                //        foreach (var sss in s.EmbeddedStream)
                //            MessageBox.Show(sss.ToString(), "Embedded Request");
                //    }
                //}
                ncounter++;

                current++;
                //pbViz.Value = current / pb * 30 + 70;




                if (ncounter >= scounter)
                {
                    break;
                }
            }


            StringBuilder sb = new StringBuilder();
            sb.Append("<!DOCTYPE html>");
            sb.AppendLine("\n<meta charset=\"UTF-8\">");
            sb.AppendLine("<style>");
            sb.AppendLine(".node circle { \n fill: #fff;\nstroke: steelblue;\nstroke-width: 1px;\n}");
            sb.AppendLine(".node text {\n font: 12px sans-serif;\ntext-color:white;\n}");
            sb.AppendLine(".link {\n fill: none;\n stroke: #ccc;\nstroke-width: 3px;\n}");
            sb.AppendLine("body{\nbackground-image: url(\"gray.png\");\n}");
            sb.AppendLine("</style>");
            sb.AppendLine("<body>");
            sb.AppendLine("<script type=\"text/javascript\" src=\"lib/d3.min.js\"></script>");
            sb.AppendLine("<script>");
            sb.AppendLine("var treeData = {\"name\" : \"HTTP-GET\", \"children\" : [");
            StreamWriter sw = new StreamWriter("traversing.txt");
            ///int itemCount = names[names.Count - 1];
            //foreach (String name in names)
            //{
            //    if (name == names.Last())
            //    {
            //        sb.AppendLine("{\"name\" :\" " + name.ToString() + "\"}");

            //    }
            //    else
            //    {
            //        sb.AppendLine("{\"name\" :\" " + name.ToString() + "\"},");
            //        if (name.ToString() == files.Select(file => Path.GetFileNameWithoutExtension(file)).ToArray().ToString())
            //        {

            //        }
            //    }

            //}






            foreach (var rhead in rHead)
            {
                if (rhead.IsMalicious)
                {
                    if (rhead.ReqType == "Head Request")
                    {
                        sw.WriteLine("*****************HEAD REQUEST*********************");
                        sw.WriteLine(rhead.UrlData.URLString);
                        sw.WriteLine(rhead.UrlData.URLReferer);
                        if (rhead.ClickStreamIndex.Count == 0 && rhead.EmbeddedStream.Count == 0)
                        {
                            if (rhead == rHead.Last())
                            { sb.AppendLine("{\"name\" : \" " + rhead.UrlData.URLString + " \"} "); }
                            else
                            { sb.AppendLine("{\"name\" : \" " + rhead.UrlData.URLString + " \"}, "); }
                        }
                        else
                        {
                            sb.AppendLine("{\"name\" : \" " + rhead.UrlData.URLString + " \", \"children\" : [");
                            //sb.AppendLine("{\"name\" : \" Click Stream \", \"children\" : [");
                            counter = rhead.ClickStreamIndex.Count;
                            if (counter == 0)
                            {
                                sb.AppendLine("{\"name\" : \" No ClickStream of this URL \"}, ");
                            }
                            else
                            {
                                for (int i = 0; i < rhead.ClickStreamIndex.Count; i++)
                                {
                                    int clickindex = rhead.ClickStreamIndex[i];
                                    sw.Write(rhead.ClickStreamIndex[i].ToString() + " ");
                                    sw.WriteLine(rHead[clickindex].UrlData.URLString);
                                    sw.WriteLine(rHead[clickindex].UrlData.URLReferer);

                                    if (rHead[clickindex].ClickStreamIndex.Count > 0)
                                    {
                                        multi = true;
                                        jcounter = rHead[i].ClickStreamIndex.Count;
                                        sb.AppendLine("{\"name\" : \" " + rHead[clickindex].UrlData.URLString + "\",\"children\" :[ ");
                                        //sb.AppendLine("{\"name\" : \" Click Stream \", \"children\" : [");
                                        for (int j = 0; j < rHead[i].ClickStreamIndex.Count; j++)
                                        {
                                            int nci = rHead[i].ClickStreamIndex[j];
                                            sb.AppendLine("{\"name\" : \" " + rHead[nci].UrlData.URLString + " \" },");
                                            if (jcounter == 1)
                                            {
                                                //if (rhead.EmbeddedStream.Count == 0)
                                                //{
                                                //    sb.AppendLine("{\"name\" : \" " + rHead[nci].UrlData.URLString + " \" }]},");
                                                //}
                                                //else
                                                //{
                                                sb.AppendLine("{\"name\" : \" " + rHead[nci].UrlData.URLString + " \" },");
                                                //}
                                            }


                                        }
                                        sb.AppendLine("{\"name\" : \" Embedded Stream \", \"children\" : [");
                                        for (int j = 0; j < rHead[i].EmbeddedStream.Count; j++)
                                        {
                                            int nei = rHead[i].EmbeddedStream[j];
                                            sb.AppendLine("{\"name\" : \" " + rHead[nei].UrlData.URLString + " \" },");
                                            if (jcounter == 1)
                                            {
                                                sb.AppendLine("{\"name\" : \" " + rHead[nei].UrlData.URLString + " \" }]}]},");
                                            }
                                        }
                                    }
                                    if (rhead.ClickStreamIndex.Count == 0)
                                    {
                                        sb.AppendLine("{\"name\" : \" " + rHead[clickindex].UrlData.URLString + " \" }]}]},");
                                    }
                                    else
                                    {
                                        sb.AppendLine("{\"name\" : \" " + rHead[clickindex].UrlData.URLString + " \" }, ");
                                    }
                                    counter--;

                                    if (counter < rhead.ClickStreamIndex.Count())
                                    {
                                        if (rhead.EmbeddedStream.Count == 0)
                                        {
                                            sb.AppendLine("{\"name\" : \" " + rHead[clickindex].UrlData.URLString + " \" }]},");
                                        }
                                        else
                                        {
                                            sb.AppendLine("{\"name\" : \" " + rHead[clickindex].UrlData.URLString + " \" }, ");
                                        }

                                    }
                                    else
                                    {
                                        sb.AppendLine("{\"name\" : \" " + rHead[clickindex].UrlData.URLString + " \" }, ");
                                    }
                                }
                            }
                        }
                        sw.WriteLine();
                        if (rhead.EmbeddedStream.Count == 0)
                        {
                            continue;
                        }
                        else
                        {
                            sb.AppendLine("{\"name\" : \" Embbeded Stream \", \"children\" : [");
                            counter = rhead.EmbeddedStream.Count;
                            for (int i = 0; i < rhead.EmbeddedStream.Count; i++)
                            {
                                int embeddedIndex = rhead.EmbeddedStream[i];
                                sw.WriteLine(embeddedIndex.ToString() + " ");
                                sw.WriteLine(rHead[embeddedIndex].UrlData.URLString);
                                sw.WriteLine(rHead[embeddedIndex].UrlData.URLReferer);
                                sb.AppendLine("{\"name\" : \" " + rHead[embeddedIndex].UrlData.URLString + " \" }, ");
                                counter--;
                                if (counter == 0)
                                {
                                    if (rhead == rHead.Last())
                                    {
                                        sb.AppendLine("{\"name\" : \" " + rHead[embeddedIndex].UrlData.URLString + " \" }]}]} ");

                                    }
                                    else
                                    {
                                        sb.AppendLine("{\"name\" : \" " + rHead[embeddedIndex].UrlData.URLString + " \" }]}]}, ");
                                    }

                                }
                            }
                        }
                        sw.WriteLine();
                    }

                }
            }
            sw.Close();
            //foreach (var m in Mal)
            //{
            //    if (m == Mal.Last())
            //    { sb.AppendLine("{\"name\" : \" " + m.URLString + " \"} "); }
            //    sb.AppendLine("{\"name\" : \" " + m.URLString + " \"} ");
            //}
            //this.ResetText();
            ////sb.AppendLine("]}");
            sb.AppendLine(" ]};");
            if (rHead.Count() > 90)
            {
                sb.AppendLine("  var margin = {top: 20, right: 90, bottom: 30, left: 90},\n width = " + rHead.Count() * 50 + " - margin.left - margin.right,\n height = " + rHead.Count() * 25 + " - margin.top - margin.bottom; ");
            }
            else
            {
                sb.AppendLine("  var margin = {top: 20, right: 90, bottom: 30, left: 90},\n width = 1500 - margin.left - margin.right,\n height = 750 - margin.top - margin.bottom; ");
            }
            sb.AppendLine("  var svg = d3.select(\"body\").append(\"svg\")\n.attr(\"width\", width + margin.right + margin.left)\n.attr(\"height\", height + margin.top + margin.bottom)\n.append(\"g\")\n.attr(\"transform\", \"translate(\"  \n + margin.left + \",\" + margin.top + \")\"); ");
            sb.AppendLine("  var i = 0,\n duration = 750,\n root;");
            sb.AppendLine("  var treemap = d3.tree().size([height, width]);");
            sb.AppendLine("  root = d3.hierarchy(treeData, function(d) { return d.children; });\nroot.x0 = height / 2;\nroot.y0 = 0;");
            sb.AppendLine("  root.children.forEach(collapse);\n\nupdate(root);");
            sb.AppendLine("function collapse(d) {\n  if(d.children) {\n    d._children = d.children\n    d._children.forEach(collapse)\n    d.children = null\n  }\n}");
            sb.AppendLine("function update(source) {");
            sb.AppendLine("  var treeData = treemap(root);");
            sb.AppendLine("  var nodes = treeData.descendants(),\nlinks = treeData.descendants().slice(1);");
            sb.AppendLine("  nodes.forEach(function(d){ d.y = d.depth * 180});");
            sb.AppendLine("  var node = svg.selectAll('g.node')\n.data(nodes, function(d) {return d.id || (d.id = ++i); });");
            sb.AppendLine("  var nodeEnter = node.enter().append('g')\n.attr('class', 'node')\n.attr(\"transform\", function(d) {\n return \"translate(\" + source.y0 + \", \" + source.x0 + \")\";\n})\n.on('click', click);");
            sb.AppendLine("  nodeEnter.append('circle')\n.attr('class', 'node')\n.attr('r', 1e-6)\n.style(\"fill\", function(d) {\nreturn d._children ? \"lightsteelblue\" : \"#fff\";\n});");
            sb.AppendLine("  nodeEnter.append('text')   \n   .attr(\"dy\", \".35em\")   \n  .attr(\"x\", function(d) {   \n      return d.children || d._children ? -13 : 13;\n   })      \n.attr(\"text-anchor\", function(d) {      \n    return d.children || d._children ? \"end\" : \"start\";      \n})      \n.text(function(d) { return d.data.name; });");
            sb.AppendLine("  var nodeUpdate = nodeEnter.merge(node);");
            sb.AppendLine("  nodeUpdate.transition()    \n.duration(duration)    \n.attr(\"transform\", function(d) {         \nreturn \"translate(\" + d.y + \",\" + d.x + \")\";     \n});");
            sb.AppendLine("  nodeUpdate.select('circle.node')    \n.attr('r', 10)    \n.style(\"fill\", function(d) {        \nswitch(d.data.name) {    ");
            foreach(var m in Mal)
            {
                sb.AppendLine("\ncase \' "+m.URLString+" \':\nreturn \"red\";\nbreak;\n");
            }

            sb.AppendLine("  default:\nreturn \"6954bc\";\n break;\n}\n})\n.attr('cursor', 'pointer');");
            sb.AppendLine("  var nodeExit = node.exit().transition()      \n.duration(duration)      \n.attr(\"transform\", function(d) {          \nreturn \"translate(\" + source.y + \",\" + source.x + \")\";      \n})      \n.remove();");
            sb.AppendLine("  nodeExit.select('circle')    \n.attr('r', 1e-6);");
            sb.AppendLine("  nodeExit.select('text  ')    \n.style('fill-opacity', 1e-6);");
            sb.AppendLine("  var link = svg.selectAll('path.link')      \n.data(links, function(d) { return d.id; });");
            sb.AppendLine("  var linkEnter = link.enter().insert('path', \"g\")      \n.attr(\"class\", \"link\")      \n.attr('d', function(d){        \nvar o = {x: source.x0, y: source.y0}        \nreturn diagonal(o, o)      \n});");
            sb.AppendLine("  var linkUpdate = linkEnter.merge(link);");
            sb.AppendLine("  linkUpdate.transition()      \n.duration(duration)      \n.attr('d', function(d){ return diagonal(d, d.parent) });");
            sb.AppendLine("  var linkExit = link.exit().transition()      \n.duration(duration)      \n.attr('d', function(d) {        \nvar o = {x: source.x, y: source.y}        \nreturn diagonal(o, o)      \n})      \n.remove();");
            sb.AppendLine("  nodes.forEach(function(d){    \nd.x0 = d.x;    \nd.y0 = d.y;  \n});");
            sb.AppendLine("  function diagonal(s, d) {\n\n    path = `M ${s.y} ${s.x}\n            C ${(s.y + d.y) / 2} ${s.x},\n              ${(s.y + d.y) / 2} ${d.x},\n              ${d.y} ${d.x}`\n\n    return path\n  }");
            sb.AppendLine("  function click(d) {\n    if (d.children) {\n        d._children = d.children;\n        d.children = null;\n      } else {\n        d.children = d._children;\n        d._children = null;\n      }\n    update(d);\n  }\n}");
            sb.AppendLine("</script>");
            sb.AppendLine("</body>");
            File.WriteAllText("Hviz.html", sb.ToString());
            Form2 frm = new Form2();
            frm.Text = cbIPS1.Text;
            urlclass.Clear();
            frm.Show();
        }


        private bool CheckMalicious(string url)
        {
            bool isMal = false;
            string line = "";
            StreamReader reader = new StreamReader("data.txt");
            while ((line = reader.ReadLine()) != null)
            {
                if ( url.Equals(line))
                    {
                    
                    {
                        isMal = true;
                        break;
                    }
                    }
            }
            return isMal;
        }




        private void pnl_server_Paint(object sender, PaintEventArgs e)
        {

        }

        private void btn_serVis_Click(object sender, EventArgs e)
        {
            visbuttonwork();
        }

        private void btn_Server_Click(object sender, EventArgs e)
        {
            pnl_server.Enabled = true;
            pnl_server.Visible = true;
            pnl_server.BringToFront();
            //if (names == null)
            //{
            //    names = Directory.GetFiles(Environment.CurrentDirectory, "*.mal").Select(file => Path.GetFileNameWithoutExtension(file)).ToArray();
            //    for (int i = 0; i < names.Count(); i++)
            //    {
            //        cbIPS1.Items.Add(names[i]);
            //    }
            //}
        }

        private void cbIPS1_SelectedIndexChanged(object sender, EventArgs e)
        {

        }
        public static string GetIPAddress()
        {
            string strHostName = System.Net.Dns.GetHostName();
            IPHostEntry ipHostInfo = Dns.Resolve(Dns.GetHostName());
            IPAddress ipAddress = ipHostInfo.AddressList[0];

            return ipAddress.ToString();
        }
        private void Btn_serGolive_Click(object sender, EventArgs e)
        {
            lbl_ipserver.Text = "Ip address of Server: "+GetIPAddress();
            btn_Stoplisten.Enabled = true;
            tah = new Thread(Accept);
            tah.Start();
        }

        private void Accept()
        {
            sock.BeginAccept(AcceptedCallback, null);
            lbl_conn.Invoke((MethodInvoker)(() => lbl_conn.Text = "Listening started on port #" + PORT));
            Btn_serGolive.Enabled = false;

        }

        private void AcceptedCallback(IAsyncResult result)
        {
           

                try
                {


                    clientSocket = sock.EndAccept(result);
                    remoteip = (((IPEndPoint)(clientSocket.RemoteEndPoint)).Address.ToString());
                    Ip = new IPEndPoint(IPAddress.Any, PORT);




                }
                catch (SocketException)
                {
                    sock.Close();
                    rtb_text.Invoke((MethodInvoker)(() => rtb_text.Text = (remoteip + " Disconnected")));

                    return;
                }
                Btn_serGolive.Invoke((MethodInvoker)(() => Btn_serGolive.Text = "Connected"));
                buf = new byte[8024];
                clientSocket.BeginReceive(buf, 0, buf.Length, SocketFlags.None, new AsyncCallback(receivedCallback), clientSocket);
                Accept();
            
        }

        private void receivedCallback(IAsyncResult result)
        {
            Socket clientSocket = result.AsyncState as Socket;
            int bufferSize = 0;
            try
            {
                bufferSize = clientSocket.EndReceive(result);

            }
            catch (SocketException)
            {
                clientSocket.Close();
            }
            byte[] packet = new byte[bufferSize];
            Array.Copy(buf, packet, packet.Length);
            try
            {
                string clientIP = ((IPEndPoint)(clientSocket.RemoteEndPoint)).Address.ToString();

                {
                    string receiveText = Encoding.Default.GetString(packet);
                    string[] separater = new string[] { "EndofPacket" };
                    string[] lines = receiveText.Split(separater, StringSplitOptions.None);
                    rtb_text.Invoke((MethodInvoker)(() => rtb_text.AppendText(Environment.NewLine + "Client: " + clientIP + "\t" + lines.Length.ToString())));
                    mutex.WaitOne();
                    {
                        StreamWriter sw = new StreamWriter(remoteip + ".log", true);
                        sw.AutoFlush = true;
                        foreach (string line in lines)
                        {
                            sw.WriteLine(line);
                        }
                        sw.Close();
                    }
                    mutex.ReleaseMutex();
                }
                buf = new byte[8024];
            }
            catch (SocketException)
            {
                Btn_serGolive.Invoke((MethodInvoker)(() => Btn_serGolive.Text = "Client forcefully disconnected"));
                rtb_text.Invoke((MethodInvoker)(() => rtb_text.Text = "Client forcefully disconnected"));
                clientSocket.Close();
                return;
            }
            buf = new byte[8024];
        }

        private void textBox1_TextChanged_2(object sender, EventArgs e)
        {
            loginusertextchange();
        }

        private void loginusertextchange()
        {
            if (tb_loginUN.Text.Length > 0 && tb_loginUN.Text.Length <= 15)
            {
                pictureBox11.Image = images[tb_loginUN.Text.Length - 1];
                pictureBox11.BackgroundImageLayout = ImageLayout.Stretch;
            }
            else if (tb_loginUN.Text.Length <= 0)
                pictureBox11.Image = Properties.Resources.debut;
            else
                pictureBox11.Image = images[22];
        }

        private void textBox2_TextChanged_2(object sender, EventArgs e)
        {
            EyeshideImage();
        }

        private void textBox1_Click_2(object sender, EventArgs e)
        {
            if (tb_loginUN.Text.Length > 0)
                pictureBox11.Image = images[tb_loginUN.Text.Length - 1];
            else
                pictureBox11.Image = Properties.Resources.debut;
        }

        private void textBox2_Click_2(object sender, EventArgs e)
        {
            EyeshideImage();

        }

        private void label2_Click(object sender, EventArgs e)
        {

        }

        private void bunifuFlatButton1_Click_1(object sender, EventArgs e)
        {
            signup_pnl.Visible = true;
        }

        private void btn_signup_Click(object sender, EventArgs e)
        {
            if(tb_SignUN.Text !="" && tb_Signpw.Text != "" && tb_signphone.Text != "")
            {

                try
                {
                    Connect obj = new Connect();
                    obj.conn.ConnectionString = obj.locate;
                    obj.conn.Open();
                    string insertUser = "insert into userTable values ('"+tb_SignUN.Text.ToString() +"','"+ tb_Signpw.Text.ToString()+"', '"+tb_signphone.Text+"')";
                  
                    obj.cmd.Connection = obj.conn;
                    obj.cmd.CommandText = insertUser;
                    
                        obj.cmd.ExecuteNonQuery();
                    obj.conn.Close();
                    MessageBox.Show("Signup Successfull","Greetings",MessageBoxButtons.OK,MessageBoxIcon.Information);
                    Signupreset();
                
                }
                catch(Exception ex)
                {
                    MessageBox.Show("Please check" + ex.Message, "Error" );
                }
            }
            else
            {
                MessageBox.Show("Please enter information correctly to continue.","Sign Up Error", MessageBoxButtons.OKCancel,MessageBoxIcon.Error);
            }
        }

        private void Signupreset()
        {
            tb_signphone.Clear();
            tb_Signpw.Clear();
            tb_SignUN.Clear();
            signup_pnl.Visible = false;
        }

        private void tn_login_Click(object sender, EventArgs e)
        {
            if (tb_loginUN.Text != "" && tb_loginPW.Text != "")
            {
                try
                {
                    Connect obj = new Connect();
                    obj.conn.ConnectionString = obj.locate;
                    obj.conn.Open();
                    SqlDataAdapter adapter = new SqlDataAdapter("SELECT COUNT (*) FROM userTable where Username ='" + tb_loginUN.Text + "' and Passwrod = '" + tb_loginPW.Text + "' ", obj.conn);
                    DataTable dt = new DataTable();
                    adapter.Fill(dt);
                    if (dt.Rows[0][0].ToString() == "1")
                    {
                        MessageBox.Show("Login Successfull", "Greetings", MessageBoxButtons.OK, MessageBoxIcon.Information);
                        SecureHvizWork();
                    }
                    else
                    {
                        MessageBox.Show("Please double check your information to continue.", "Login Error", MessageBoxButtons.OKCancel, MessageBoxIcon.Error);
                    }

                    
                }
                catch(Exception ex)
                {
                    MessageBox.Show("Please check" + ex.Message, "Error");
                }
            }
            else
            {
                MessageBox.Show("Please enter information correctly to continue.", "Login Error", MessageBoxButtons.OKCancel, MessageBoxIcon.Error);
            }
        }

        private void SecureHvizWork()
        {
            btn_vislive.Enabled = true;
            btn_offvis.Enabled = true;
            btn_Server.Enabled = true;
        }

        private void lbl_loginforget_LinkClicked(object sender, LinkLabelLinkClickedEventArgs e)
        {
            System.Diagnostics.Process.Start("https://www.facebook.com/talhav1.0");
        }

        private void timer1_Tick(object sender, EventArgs e)
        {
            lbl_clock.Text = DateTime.Now.ToString("T");
        }

        private void bunifuImageButton17_Click(object sender, EventArgs e)
        {
            Application.Exit();
        }

        private void bunifuImageButton18_Click(object sender, EventArgs e)
        {
            this.WindowState = FormWindowState.Minimized;
        }

        private void bunifuImageButton19_Click(object sender, EventArgs e)
        {
            if (WindowState.ToString() == "Normal")
            {
                this.WindowState = FormWindowState.Maximized;
            }
            else
            {
                this.WindowState = FormWindowState.Normal;
            }
        }

        private void tb_Signpw_TextChanged(object sender, EventArgs e)
        {

        }

        private void tb_SignUN_TextChanged(object sender, EventArgs e)
        {

        }

        private void pictureBox13_Click(object sender, EventArgs e)
        {

        }

        private void pictureBox15_Click(object sender, EventArgs e)
        {

        }

        private void pictureBox12_Click(object sender, EventArgs e)
        {

        }

        private void pictureBox14_Click(object sender, EventArgs e)
        {

        }

        private void cb_showloginPW_CheckedChanged(object sender, EventArgs e)
        {
            if (tb_loginPW.PasswordChar == '*')
            {
                tb_loginPW.PasswordChar = '\0';
            }
            else
            {
                tb_loginPW.PasswordChar = '*';
            }
        }

      

        private void checkBox1_CheckedChanged(object sender, EventArgs e)
        {
            if (tb_Signpw.PasswordChar == '*')
            {
                tb_Signpw.PasswordChar = '\0';
            }
            else
            {
                tb_Signpw.PasswordChar = '*';
            }
        }

        private void groupBox3_Enter(object sender, EventArgs e)
        {

        }

        private void btn_serVis_Click_1(object sender, EventArgs e)
        {
            lbl_malreq.Invoke(new Action(() => { lbl_malreq.Text = "Analyzing file please wait"; }));
            visbuttonwork();
        }


        private void btn_MalClear_Click(object sender, EventArgs e)
        {

            cbIPS1.Text = "";
            rtb_malact.Text = "";
            lbl_malreq.Invoke(new Action(() => { lbl_malreq.Text = "Funtion Reset"; }));
        }

        private void btn_showFilesMal_Click(object sender, EventArgs e)
        {
            lv_checkmal.Items.Clear();
            string[] filenames = Directory.GetFiles(Environment.CurrentDirectory, "*.log").Select(file => Path.GetFileNameWithoutExtension(file)).ToArray();
            
                foreach (string a in filenames)
                {
                    ListViewItem item = new ListViewItem(a.ToString());
                    lv_checkmal.Invoke(new Action(() => lv_checkmal.Items.Insert(0, item)));
                }
                this.Refresh();
            button2.Enabled = true;
            button1.Enabled = true;
        }

        private void button1_Click(object sender, EventArgs e)
        {
            checkmalReq();
        }

        private async void checkmalReq()
        {
           Task tk= new Task(()=> checkmal());
            tk.Start();
            await tk;
        }

        private void checkmal()
        {
            lbl_malcheck.Invoke(new Action(() => { lbl_malcheck.Text = "Analyzing files please wait"; }));
            string[] filenames1 = Directory.GetFiles(Environment.CurrentDirectory, "*.log");

            foreach (string file in filenames1)
            {

                string temp1 = "";

                StreamReader sr1 = new StreamReader(file);
                while (sr1.Peek() > 0)
                {
                    temp1 = sr1.ReadLine().Trim();

                    URLClass urlData = new URLClass();
                    if (temp1.Length > 0)
                    {

                        string[] data = temp1.ToString().Split('|');
                        urlData.URLString = data[2];
                        //urlData.URLReferer = data[3];
                        //urlData.ContentType = Convert.ToString(data[4]);
                        //check urlData.UrlString is malicious or not
                        // Thread malth = new Thread();
                        urlclass.Add(urlData);

                    }

                }
                sr1.Dispose();
                foreach (var a in urlclass)
                {
                    a.IsMalicious = CheckMalicious(a.URLString);
                    if (a.IsMalicious)
                    {

                        File.Move(file, Path.ChangeExtension(file, ".mal"));
                        lbl_malcheck.Invoke(new Action(() => { lbl_malcheck.Text = "System reading file please wait."; }));
                        break;

                    }
                }
            }
            MessageBox.Show("All files are succesfully readed", "Greetings", MessageBoxButtons.OK, MessageBoxIcon.Information);

        }

        private void btn_Refresh_Click(object sender, EventArgs e)
        {
            btn_MalClear.Enabled = true;
                names = Directory.GetFiles(Environment.CurrentDirectory, "*.mal").Select(file => Path.GetFileNameWithoutExtension(file)).ToArray();
                for (int i = 0; i < names.Count(); i++)
                {
                    cbIPS1.Items.Add(names[i]);
                }
            
        }

        private void button2_Click(object sender, EventArgs e)
        {
            lv_checkmal.Items.Clear();
            string[] filenames = Directory.GetFiles(Environment.CurrentDirectory, "*.log").Select(file => Path.GetFileNameWithoutExtension(file)).ToArray();

            foreach (string a in filenames)
            {
                ListViewItem item = new ListViewItem(a.ToString());
                lv_checkmal.Invoke(new Action(() => lv_checkmal.Items.Insert(0, item)));
            }
            this.Refresh();
        }

        private void btn_Stoplisten_Click(object sender, EventArgs e)
        {
            try
            {
                sock.Disconnect(true);
                sock.Close();
                sock.Dispose();
                
                
            }
            catch (Exception ex)
            {
                MessageBox.Show("Please check" + ex.Message,"Socket Connection Error",MessageBoxButtons.OK);
            }
            btn_Stoplisten.Enabled = false;
            Btn_serGolive.Enabled = true;
        }

        private void ListV_live_SelectedIndexChanged(object sender, EventArgs e)
        {

        }

        public void visoffline()
        {
            foreach (var x in URLData)

            {
                HeadRequestClass hrc = new HeadRequestClass();

                // for head requests
                if (x.URLReferer == null && (x.ContentType.Contains("text/html") || x.ContentType.Contains("text/xhtml")))
                {

                    hrc.ReqType = "Head Request";
                    hrc.UrlData = x;
                    rHead.Add(hrc);
                }
                // for click requests
                else if (x.URLReferer != null && (x.ContentType.Contains("text/html") || x.ContentType.Contains("text/xhtml")))
                {
                    hrc.ReqType = "Click Stream Request";
                    hrc.UrlData = x;
                    rHead.Add(hrc);

                    for (int i = rHead.Count - 2; i > -1; --i)
                    {
                        if (x.URLReferer.EndsWith(rHead[i].UrlData.URLString.Trim()))
                        {
                            rHead[i].ClickStreamIndex.Add(rHead.Count - 1);
                            break;
                        }
                    }
                }

                // for embedded requests
                else
                {
                    hrc.ReqType = "Embedded Request";
                    hrc.UrlData = x;
                    rHead.Add(hrc);
                    if (x.URLReferer != null)
                    {
                        for (int i = rHead.Count - 2; i > -1; --i)
                        {
                            if (x.URLReferer.EndsWith(rHead[i].UrlData.URLString.Trim()))
                            {
                                rHead[i].EmbeddedStream.Add(rHead.Count - 1);
                                break;
                            }
                        }
                    }

                }

            }

            //MessageBox.Show("sad");

            //for (int i = 0; i < rHead.Count; i++)
            //{
            //    if (rHead[i].ReqType == "Head Request")
            //    {
            //        MessageBox.Show(i.ToString());
            //    }

            //}

            //foreach (var s in rHead)
            //{
            //    if (s.ReqType == "Head Request")
            //    {

            //        //foreach (var ss in s.ClickStreamIndex)
            //        //    MessageBox.Show(ss.ToString(), "Click Stream Request No");

            //        //foreach (var sss in s.EmbeddedStream)
            //        //    MessageBox.Show(sss.ToString(), "Embedded Request");
            //    }
            //}

            StringBuilder sb = new StringBuilder();
            sb.Append("<!DOCTYPE html>");
            sb.AppendLine("\n<meta charset=\"UTF-8\">");
            sb.AppendLine("<style>");


            sb.AppendLine(".node circle { \n fill: #fff;\nstroke: steelblue;\nstroke-width: 1px;\n}");
            sb.AppendLine(".node text {\n font: 12px sans-serif;\ntext-color: white;\n}");
            sb.AppendLine(".link {\n fill: none;\n stroke: #ccc;\nstroke-width: 3px;\n}");
            sb.AppendLine("body{\nbackground-image: url(\"gray.png\");\n}");
            sb.AppendLine("</style>");
            sb.AppendLine("<body>");
            sb.AppendLine("<script type=\"text/javascript\" src=\"lib/d3.min.js\"></script>");
            sb.AppendLine("<script>");
            sb.AppendLine("var treeData = {\"name\" : \"HTTP-GET\", \"children\" : [");
            //MessageBox.Show(rHead.Count.ToString());
            StreamWriter sw = new StreamWriter("traversing.txt");
            foreach (var rhead in rHead)
            {
                if (rhead.ReqType == "Head Request")
                {
                    sw.WriteLine("*****************HEAD REQUEST*********************");
                    sw.WriteLine(rhead.UrlData.URLString);
                    sw.WriteLine(rhead.UrlData.URLReferer);
                    if (rhead.ClickStreamIndex.Count == 0)
                    {
                        if (rhead == rHead.Last())
                        { sb.AppendLine("{\"name\" : \" " + rhead.UrlData.URLString + " \"} "); }
                        else
                        { sb.AppendLine("{\"name\" : \" " + rhead.UrlData.URLString + " \"}, "); }
                    }
                    else
                    {
                        sb.AppendLine("{\"name\" : \" " + rhead.UrlData.URLString + " \", \"children\" : [");
                        //sb.AppendLine("{\"name\" : \" Click Stream \", \"children\" : [");
                        counter = rhead.ClickStreamIndex.Count;
                        for (int i = 0; i < rhead.ClickStreamIndex.Count; i++)
                        {
                            int clickindex = rhead.ClickStreamIndex[i];
                            sw.Write(rhead.ClickStreamIndex[i].ToString() + " ");
                            sw.WriteLine(rHead[clickindex].UrlData.URLString);
                            sw.WriteLine(rHead[clickindex].UrlData.URLReferer);

                            if (rHead[clickindex].ClickStreamIndex.Count > 0)
                            {
                                multi = true;
                                jcounter = rHead[i].ClickStreamIndex.Count;
                                sb.AppendLine("{\"name\" : \" " + rHead[clickindex].UrlData.URLString + "\",\"children\" :[ ");
                                //sb.AppendLine("{\"name\" : \" Click Stream \", \"children\" : [");
                                for (int j = 0; j < rHead[i].ClickStreamIndex.Count; j++)
                                {
                                    int nci = rHead[i].ClickStreamIndex[j];
                                    sb.AppendLine("{\"name\" : \" " + rHead[nci].UrlData.URLString + " \" },");
                                    if (jcounter == 1)
                                    {
                                        sb.AppendLine("{\"name\" : \" " + rHead[nci].UrlData.URLString + " \" },");
                                    }


                                }
                                sb.AppendLine("{\"name\" : \" Embedded Stream \", \"children\" : [");
                                for (int j = 0; j < rHead[i].EmbeddedStream.Count; j++)
                                {
                                    int nei = rHead[i].EmbeddedStream[j];
                                    sb.AppendLine("{\"name\" : \" " + rHead[nei].UrlData.URLString + " \" },");
                                    if (jcounter == 1)
                                    {
                                        sb.AppendLine("{\"name\" : \" " + rHead[nei].UrlData.URLString + " \" }]}]},");
                                    }
                                }
                            }
                            sb.AppendLine("{\"name\" : \" " + rHead[clickindex].UrlData.URLString + " \" }, ");
                            counter--;
                            if (counter == 0)
                            {
                                sb.AppendLine("{\"name\" : \" " + rHead[clickindex].UrlData.URLString + " \" }, ");
                            }
                        }
                    }
                    sw.WriteLine();
                    if (rhead.EmbeddedStream.Count == 0)
                    {
                        continue;
                    }
                    else
                    {
                        sb.AppendLine("{\"name\" : \" Embbeded Stream \", \"children\" : [");
                        counter = rhead.EmbeddedStream.Count;
                        for (int i = 0; i < rhead.EmbeddedStream.Count; i++)
                        {
                            int embeddedIndex = rhead.EmbeddedStream[i];
                            sw.WriteLine(embeddedIndex.ToString() + " ");
                            sw.WriteLine(rHead[embeddedIndex].UrlData.URLString);
                            sw.WriteLine(rHead[embeddedIndex].UrlData.URLReferer);
                            sb.AppendLine("{\"name\" : \" " + rHead[embeddedIndex].UrlData.URLString + " \" }, ");
                            counter--;
                            if (counter == 0)
                            {
                                if (multi == true)
                                {
                                    sb.AppendLine("{\"name\" : \" " + rHead[embeddedIndex].UrlData.URLString + " \" }]}, ");

                                }
                                else
                                {
                                    sb.AppendLine("{\"name\" : \" " + rHead[embeddedIndex].UrlData.URLString + " \" }]}, ");
                                }
                            }
                        }
                    }
                    sw.WriteLine();
                }
                // sb.AppendLine("]}");
            }
            sw.Close();
            sb.AppendLine("]}]}]};");
            sb.AppendLine("  var margin = {top: 20, right: 90, bottom: 30, left: 90},\n width = 1960 - margin.left - margin.right,\n height = 500 - margin.top - margin.bottom; ");
            sb.AppendLine("  var svg = d3.select(\"body\").append(\"svg\")\n.attr(\"width\", width + margin.right + margin.left)\n.attr(\"height\", height + margin.top + margin.bottom)\n.append(\"g\")\n.attr(\"transform\", \"translate(\"  \n + margin.left + \",\" + margin.top + \")\"); ");
            sb.AppendLine("  var i = 0,\n duration = 750,\n root;");
            sb.AppendLine("  var treemap = d3.tree().size([height, width]);");
            sb.AppendLine("  root = d3.hierarchy(treeData, function(d) { return d.children; });\nroot.x0 = height / 2;\nroot.y0 = 0;");
            sb.AppendLine("  root.children.forEach(collapse);\n\nupdate(root);");
            sb.AppendLine("function collapse(d) {\n  if(d.children) {\n    d._children = d.children\n    d._children.forEach(collapse)\n    d.children = null\n  }\n}");
            sb.AppendLine("function update(source) {");
            sb.AppendLine("  var treeData = treemap(root);");
            sb.AppendLine("  var nodes = treeData.descendants(),\nlinks = treeData.descendants().slice(1);");
            sb.AppendLine("  nodes.forEach(function(d){ d.y = d.depth * 180});");
            sb.AppendLine("  var node = svg.selectAll('g.node')\n.data(nodes, function(d) {return d.id || (d.id = ++i); });");
            sb.AppendLine("  var nodeEnter = node.enter().append('g')\n.attr('class', 'node')\n.attr(\"transform\", function(d) {\n return \"translate(\" + source.y0 + \", \" + source.x0 + \")\";\n})\n.on('click', click);");
            sb.AppendLine("  nodeEnter.append('circle')\n.attr('class', 'node')\n.attr('r', 1e-6)\n.style(\"fill\", function(d) {\nreturn d._children ? \"lightsteelblue\" : \"#fff\";\n});");
            sb.AppendLine("  nodeEnter.append('text')   \n   .attr(\"dy\", \".35em\")   \n  .attr(\"x\", function(d) {   \n      return d.children || d._children ? -13 : 13;\n   })      \n.attr(\"text-anchor\", function(d) {      \n    return d.children || d._children ? \"end\" : \"start\";      \n})      \n.text(function(d) { return d.data.name; });");
            sb.AppendLine("  var nodeUpdate = nodeEnter.merge(node);");
            sb.AppendLine("  nodeUpdate.transition()    \n.duration(duration)    \n.attr(\"transform\", function(d) {         \nreturn \"translate(\" + d.y + \",\" + d.x + \")\";     \n});");
            sb.AppendLine("  nodeUpdate.select('circle.node')    \n.attr('r', 10)    \n.style(\"fill\", function(d) {        \nswitch(d.data.name) { \ncase \' wah.comsats.edu.pk/ \':\nreturn \"red\";\nbreak;    ");
            //if(true)//malicious activity
            //{
            //sb.AppendLine("\ncase \' DataGoesHere \':\nreturn \"red\";\nbreak;\n");
            //}

            sb.AppendLine("  default:\nreturn \"6954bc\";\n break;\n}\n})\n.attr('cursor', 'pointer');");
            sb.AppendLine("  var nodeExit = node.exit().transition()      \n.duration(duration)      \n.attr(\"transform\", function(d) {          \nreturn \"translate(\" + source.y + \",\" + source.x + \")\";      \n})      \n.remove();");
            sb.AppendLine("  nodeExit.select('circle')    \n.attr('r', 1e-6);");
            sb.AppendLine("  nodeExit.select('text')    \n.style('fill-opacity', 1e-6);");
            sb.AppendLine("  var link = svg.selectAll('path.link')      \n.data(links, function(d) { return d.id; });");
            sb.AppendLine("  var linkEnter = link.enter().insert('path', \"g\")      \n.attr(\"class\", \"link\")      \n.attr('d', function(d){        \nvar o = {x: source.x0, y: source.y0}        \nreturn diagonal(o, o)      \n});");
            sb.AppendLine("  var linkUpdate = linkEnter.merge(link);");
            sb.AppendLine("  linkUpdate.transition()      \n.duration(duration)      \n.attr('d', function(d){ return diagonal(d, d.parent) });");
            sb.AppendLine("  var linkExit = link.exit().transition()      \n.duration(duration)      \n.attr('d', function(d) {        \nvar o = {x: source.x, y: source.y}        \nreturn diagonal(o, o)      \n})      \n.remove();");
            sb.AppendLine("  nodes.forEach(function(d){    \nd.x0 = d.x;    \nd.y0 = d.y;  \n});");
            sb.AppendLine("  function diagonal(s, d) {\n\n    path = `M ${s.y} ${s.x}\n            C ${(s.y + d.y) / 2} ${s.x},\n              ${(s.y + d.y) / 2} ${d.x},\n              ${d.y} ${d.x}`\n\n    return path\n  }");
            sb.AppendLine("  function click(d) {\n    if (d.children) {\n        d._children = d.children;\n        d.children = null;\n      } else {\n        d.children = d._children;\n        d._children = null;\n      }\n    update(d);\n  }\n}");
            sb.AppendLine("</script>");
            sb.AppendLine("</body>");
            File.WriteAllText("Hviz.html", sb.ToString());
            Form2 frm = new Form2();
            frm.Show();
        }

        private void btn_offvis_Click(object sender, EventArgs e)
        {
            vo.Show();
            //visoffline();
        }
    }
}


