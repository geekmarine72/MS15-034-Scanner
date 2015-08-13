// <author>Paul Vilevac</author>
// <date>04/15/2015 10:31 AM PST</date>

namespace IIS_SCAN
{
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.Net;
    
    
    class Program
    {
        /// <summary>
        /// Scans one or more websites including virtuals to determine if the host is vulnerable for the MS15-034 vulnerability in a non-destructive manner. Emits a CSV suitable for reporting.
        /// </summary>
        /// <remarks>
        /// HTTP.sys Remote Code Execution Vulnerability - CVE-2015-1635
        ///<para>
        /// A remote code execution vulnerability exists in the HTTP protocol stack (HTTP.sys) that is caused when HTTP.sys improperly parses specially crafted HTTP requests. An attacker who successfully exploited this vulnerability could execute arbitrary code in the context of the System account.
        ///</para>
        ///<para>
        /// To exploit this vulnerability, an attacker would have to send a specially crafted HTTP request to the affected system. The update addresses the vulnerability by modifying how the Windows HTTP stack handles requests.
        ///</para>
        ///<para>
        /// Source: https://technet.microsoft.com/en-us/library/security/ms15-034.aspx
        ///</para>
        /// </remarks>
        /// <example> 
        /// <code> 
        /// <![CDATA[
        /// iis-scan.exe http://localhost,https://127.0.01,http://www.mytarget.com:8080,https://alt.mytarget.com/subsite
        /// ]]>
        public static string logname = "";
        static bool probeAll = false;

        static void Main(string[] args)
        {
            logname = String.Format("iis-scan {0}-{1}-{2} {3}-{4}-{5}.log", System.DateTime.Now.Year,System.DateTime.Now.Month,System.DateTime.Now.Day,System.DateTime.Now.Hour,System.DateTime.Now.Minute,System.DateTime.Now.Second );
            var scans = new List<Scan>();
            try
            {
                var assemblyName = typeof(Program).Assembly.GetName();
                log("{0} version {1}", assemblyName.Name.ToString(), assemblyName.Version.ToString());
                if (args.GetUpperBound(0) < 0)
                {
                    Console.WriteLine("");
                    Console.WriteLine("usage:  IIS-SCAN URL1[,URL2,URL3,...URLx] [/y]");
                    Console.WriteLine("Probes a web server for the MS15-034 HTTP.SYS driver vulnerability");
                    Console.WriteLine("");
                    Console.WriteLine("URL1[,URL2,URL3,...URLx] - one or more (comma delimitted) urls including protocol, host, and port.");
                    Console.WriteLine("[/y] - optional flag, if set, will probe web server even if header indicates it is NOT an IIS server.");

                }
                else
                {
                    Console.WriteLine("Writing log to {0}.", logname);
                    
                     foreach(string arg in args)
                    {
                        if (String.IsNullOrEmpty(arg.Trim()))
                            break;

                        if (arg.Contains(","))
                        {
                            var urls = arg.Split(',');
                            foreach (string url in urls)
                            {
                                var target = url.Trim();
                                if (!String.IsNullOrEmpty(target))
                                    scans.Add(new Scan(target));
                            }
                        }
                        else if (arg.ToLower() == "/y")
                        {
                            probeAll = true;
                        }
                        else
                        {
                            var target = arg.Trim();
                            if(!String.IsNullOrEmpty(target))
                                scans.Add(new Scan(target));
                        }
                    }
                     
                   
                }
            }
            catch(Exception ex)
            {
                log("An exception occurred!");
                log(ex.ToString());
            }

            log("Starting scans");
            foreach (Scan scan in scans)
            {
                
                scan.Test(probeAll);
                log("{0}:{1} - {2}", scan.Target, scan.Result.ToString(), scan.IsVulnerable.HasValue? (scan.IsVulnerable.Value? "#VULNERABLE#" : "*secure*") : "not tested");
            }
            log("Scans complete");
            WriteResults(scans);
            Console.WriteLine("Press enter to exit");
            Console.ReadLine();

        }
        static void log(string data)
        {
            string timestamp = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss.fff");
            using(TextWriter tw = File.AppendText(logname))
            {
                
                var entry = String.Format("{0}: {1}", timestamp, data);
                Console.WriteLine(data);
                tw.WriteLine(entry);
                tw.Flush();
                tw.Close();
            }
        }
        static void log(string format, params string[] arg)
        {
            log(String.Format(format, arg));
        }
        static void WriteResults(List<Scan> scans)
        {
            var results = String.Format("iis-scan-results {0}-{1}-{2} {3}-{4}-{5}.csv", System.DateTime.Now.Year, System.DateTime.Now.Month, System.DateTime.Now.Day, System.DateTime.Now.Hour, System.DateTime.Now.Minute, System.DateTime.Now.Second);
            using(TextWriter tw = new StreamWriter(new FileStream(results, FileMode.Create, FileAccess.Write, FileShare.None)))
            {
                tw.WriteLine(Scan.Header());
                foreach(Scan scan in scans)
                {
                    tw.WriteLine(scan.ToString());
                }
            }
            log("Wrote detailed results to {0}", results);

        }

       
      
    }
}
