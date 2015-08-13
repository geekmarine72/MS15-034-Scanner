using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;

namespace IIS_SCAN
{
    public class Scan
    {
        private static string ProbeRequest = "GET / HTTP/1.0\r\n\r\n";
        private static string TestRequest = "GET / HTTP/1.1\r\nHost: stuff\r\nRange: bytes=0-18446744073709551615\r\n\r\n";

        public string Url { get; private set; }
        public string Target { get; private set; }
        public string Scheme { get; private set; }
        public string Host { get; private set; }
        public int Port { get; private set; }
        public IPAddress IP { get; private set; }
        public bool IsSecure { get; private set; }
        public bool? IsVulnerable { get; private set; }
        public Results Result { get; set; }
        public string ResultDetails { get; private set; }
        private IPEndPoint IPEndPoint { get; set; }

        public Scan(string url)
        {
            Result = Results.NotScanned;

            Url = Url.IsIP() |  !url.IsUrl() ? "https://" + url : url;
            
            var uri = new Uri(Url);
            Host = uri.Host;
            Scheme  =uri.Scheme;
            IsSecure = Scheme.ToLower() == "https";

            IsVulnerable = null;
                     

            Port = uri.Port;
            Target = String.Format("{0}://{1}:{2}", Scheme, Host, Port);

            if (Scheme.ToLower() != "http" && Scheme.ToLower() != "https")
            {
                Result = Results.BadProtocol;
                ResultDetails = "Protocol detected was neither HTTP nor HTTPS";
                return;
            }
            
            try
            {
                IPAddress tempIP = new IPAddress(1);
                if (IPAddress.TryParse(Host, out tempIP))
                {
                    IP = tempIP;
                }
                else
                {
                    IPHostEntry he = Dns.GetHostEntry(Host);
                    IP = he.AddressList.First(a => a.AddressFamily == AddressFamily.InterNetwork);
                }

                IPEndPoint = new IPEndPoint(IP, Port);
            }
            catch (SocketException)
            {
                ResultDetails = "Failed to resolve hostname to IP";
            }
        }

        public void Test(bool probeAll)
        {
            if (Result == Results.NotScanned)
            {
                if (IsSecure)
                    HttpsProbe(probeAll);
                else
                    HttpProbe(probeAll);
            }
        }

        public enum Results
        {
            NotScanned,
            BadHostname,
            BadProtocol,
            ConnectFailed, 
            Probing,
            ProbeFailed,
            ProbeCompleted,
            Testing,
            TestFailed,
            TestCompleted
        }

        public override string ToString()
        {
            return String.Format("{0},{1},{2},{3},{4},{5},{6},{7},{8},{9}", Url,Target, Scheme, Host, Port, IP, IsSecure, IsVulnerable, Result, ResultDetails);
        }

        public static string Header()
        {
            return String.Format("{0},{1},{2},{3},{4},{5},{6},{7},{8},{9}", "Url", "Target", "Scheme", "Host", "Port", "IP", "IsSecure", "IsVulnerable", "Result", "ResultDetails");
        }

        private void HttpsProbe(bool probeAll)
        {
            HTTPSSocket ssocket = new HTTPSSocket();
            Result = Results.Probing;
            try
            {
                var response1 = ssocket.Get(IPEndPoint, ProbeRequest);
                Result = Results.ProbeCompleted;
                if (response1.Header.Contains("IIS") | probeAll)
                {
                    Result = Results.Testing;
                    try
                    {
                        var response2 = ssocket.Get(IPEndPoint, TestRequest);
                        Result = Results.TestCompleted;
                        IsVulnerable = response2.Header.Contains("Requested Range Not Satisfiable");
                    }
                    catch(Exception ex)
                    {
                        Result = Results.TestFailed;
                        ResultDetails = ex.Message;
                    }
                }
            }
            catch(Exception ex)
            {
                Result = Results.ProbeFailed;
                ResultDetails = ex.Message;
            }


        }
        private void HttpProbe(bool probeAll)
        {
            Result = Results.Probing;
            try
            {
                var r1 = HTTPSocket.Get(IPEndPoint, ProbeRequest);
                Result = Results.ProbeCompleted;
                if (r1.Header.Contains("IIS") | probeAll)
                {
                    Result = Results.Testing;
                    try
                    {
                        var r2 = HTTPSocket.Get(IPEndPoint, TestRequest);
                     Result = Results.TestCompleted;
                     IsVulnerable = r2.Header.Contains("Requested Range Not Satisfiable");
                    }
                    catch (Exception ex)
                    {
                        Result = Results.TestFailed;
                        ResultDetails = ex.Message;
                    }
                }
            }
            catch(Exception ex)
            {
                Result = Results.ProbeFailed;
                ResultDetails = ex.Message;
            }
        }
    }

}

