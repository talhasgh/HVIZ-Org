using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace desiging
{
    class HeadRequestClass : URLClass
    {
        public HeadRequestClass()
        {
            UrlData = new URLClass();
            clickStreamIndex = new List<int>();
            embeddedStream = new List<int>();
        }

        private URLClass urlData;




        public List<int> ClickStreamIndex { get => clickStreamIndex; set => clickStreamIndex = value; }
        public List<int> EmbeddedStream { get => embeddedStream; set => embeddedStream = value; }
        internal URLClass UrlData { get => urlData; set => urlData = value; }
        public string ReqType { get => reqType; set => reqType = value; }

        private List<int> clickStreamIndex;


        private List<int> embeddedStream;

        string reqType;
       
        
    }
}
