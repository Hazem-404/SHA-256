using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace SHAWeb.Models
{
    public class msg
    {

        public string name { get; set; }

        public string cry { get; set; }

        public string res { get; set; }

        public class ContentViewModel
        {
            public int ID { get; set; }
            public string Title { get; set; }
            public string Description { get; set; }
            
            public string Contents { get; set; }
            public byte[] Image { get; set; }
        }

    }
}
