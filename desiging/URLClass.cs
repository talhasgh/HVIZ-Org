using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace desiging
{
    class URLClass  
    {
        public URLClass()
        {
            
        }

        //packet count
        private int pktCount;
        public int PktCount
        {
            get { return pktCount; }
            set { pktCount = value; }
        }

        //URL accessed
        private string uRLString;
        public string URLString
        {
            get { return uRLString; }
            set { uRLString = value; }
        }

        //Is URL malicious

        bool isMalicious;
        public bool IsMalicious { get => isMalicious; set => isMalicious = value; }

        //Referer
        private string uRLReferer;
        public string URLReferer
        {
            get { return uRLReferer; }
            set { uRLReferer = value; }
        }


        //source IP of HTTP request
        private string sourceIP;
        public string SourceIP
        {
            get { return sourceIP; }

            set
            {
                sourceIP = value;
            }
        }



        //packet arrival time
        private DateTime pktTime;
        public DateTime PktTime
        {
            get
            {
                return pktTime;
            }

            set
            {
                pktTime = value;
            }
        }

        //HTTP method
        private string httpMethod;
        public string HttpMethod
        {
            get
            {
                return httpMethod;
            }

            set
            {
                httpMethod = value;
            }
        }

        //HTTP version
        private string httpVersion;
        public string HttpVersion
        {
            get
            {
                return httpVersion;
            }

            set
            {
                httpVersion = value;
            }
        }

        //cookie
        private string httpCookie;
        public string HttpCookie
        {
            get
            {
                return httpCookie;
            }

            set
            {
                httpCookie = value;
            }
        }

        //user-agent

        private string userAgent;
        public string UserAgent
        {
            get
            {
                return userAgent;
            }

            set
            {
                userAgent = value;
            }
        }


        //content type
        private string contentType;
        public string ContentType
        {
            get
            {
                return contentType;
            }

            set
            {
                contentType = value;
            }
        }


        //connection type
        private string connectionType;
        public string ConnectionType
        {
            get
            {
                return connectionType;
            }

            set
            {
                connectionType = value;
            }
        }
        private string hReq;
        public string HeadR
        {
            get { return hReq; }
            set { hReq = value; }
        }
        private string hclick;
        public string clickR
        {
            get { return hclick; }
            set { hclick = value; }
        }
        private string hemb;
        public string embR
        {
            get { return hemb; }
            set { hemb = value; }
        }
        private string https;
        public string HTTPS
        {
            get { return https; }
            set { https = value; }
        }
        public bool IsMalFP
        {
            get { return IsMalFP; }
            set { IsMalFP = value; }
        }
        
   
    }
}

