using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace IIS_SCAN
{
    public static class Extension
    {
        public static bool IsUrl(this string value)
        {
            string pattern = @"https?:\/\/?";
            return Regex.Match(value, pattern, RegexOptions.IgnoreCase).Success;
        }

        public static bool IsIP(this string value)
        {
            IPAddress tempIP = new IPAddress(1);
            return IPAddress.TryParse(value, out tempIP);
        }
    }
}
