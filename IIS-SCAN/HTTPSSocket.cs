

namespace IIS_SCAN
{
    using System;
    using System.Linq;
    using System.Net;
    using System.Net.Sockets;

    public class HTTPSSocket
    {
        Response response = new Response();
        Socket m_sock;
        int m_BodyLen=-1;
        int m_CurrBodyLen=0;
        string m_Data;
        bool m_Connected=false;
        Response m_response = null;
        internal Response Get(IPEndPoint ipEndpoint, string request)
        {

            m_response = new Response();

                m_sock = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
                try
                {
                    m_sock.Connect(ipEndpoint);
                }
                catch(SocketException ex)
                {
                    Console.WriteLine("Connection Failed. Cause: " + ex.Message);
                    return m_response;
                }
            
                SSL.Client.SSLConnection conn = new SSL.Client.SSLConnection();
            
                conn.DoWrite = new SSL.Client.WriteSSL(Send);
                conn.DoPlainData = new SSL.Client.PlainData(OnPlainData);
                conn.DoRenegotiate = new SSL.Client.NewCertificate(Renegotiate);
                conn.DoServerCertVerify = new SSL.Client.VerifyServCert(ServerCertVerify);
                conn.DoHandShakeSuccess = new SSL.Client.HandShakeSuccess(HandShakeSuccess);

                try
                {
                    conn.InitiateHandShake(ipEndpoint.Address.ToString(), null, SSL.Common.Misc.SecurityProviderProtocol.PROT_TLS1, Guid.Empty);
                    int MaxChunkSize = conn.MaxInitialChunkSize;
                    byte[] data = new Byte[MaxChunkSize];
                    int ActualSize=0;
                    while(!m_Connected)
                    {
                        if(!m_sock.Poll(1000*1000*4, SelectMode.SelectRead)) //give 4 secs for server to respond
                        {
                            Console.WriteLine("Server failed to respond to SSL HandShake.");
                            return response;
                        }
                        ActualSize = m_sock.Receive(data, 0, MaxChunkSize, SocketFlags.None);
                        conn.DecryptData(data, ActualSize, Guid.Empty);
                    }


                    string Request = request;

                    data = System.Text.ASCIIEncoding.ASCII.GetBytes(Request);
                    conn.EncryptSend(data, data.Length, Guid.Empty);
                    MaxChunkSize = conn.MaxDataChunkSize;
                    data = new Byte[MaxChunkSize];
                    while(m_CurrBodyLen != m_BodyLen)
                    {
                        try
                        {
                            ActualSize = m_sock.Receive(data, 0, MaxChunkSize, SocketFlags.None);
                            conn.DecryptData(data, ActualSize, Guid.Empty);
                        }
                        catch(SSL.Common.Exceptions.SSLServerDisconnectedException)
                        {
                            Console.WriteLine("Connection lost.");
                        }
                    }

                    
                    conn.Disconnect(Guid.Empty);
                    conn.Dispose();
                }
                catch(SocketException ex)
                {
                    //Console.WriteLine(ex.Message);
                }
                catch(SSL.Common.Exceptions.SSLException ex)
                {
                    //Console.WriteLine(ex.Message);
                }
                m_BodyLen = -1;
                m_CurrBodyLen = 0;
                m_Data = "";
                m_Connected = false;
                return m_response;
            
        }
        private bool Send(byte[] data, object state)
        {
            int i = m_sock.Send(data, 0, data.Length, SocketFlags.None);
            return true;
        }
        private void OnPlainData(Byte[] data, object state)
        {
            //m_response = new Response();

            string Data = System.Text.ASCIIEncoding.ASCII.GetString(data, 0, data.Length);
            m_Data += Data;
            int BodyStart = -1;
            if(m_BodyLen == -1)
            {
                BodyStart = m_Data.IndexOf("\r\n\r\n");
                int PosStart = m_Data.IndexOf("Content-Length: ");
                int PosEnd = -1;
                if(PosStart != -1)
                {
                    PosEnd = m_Data.IndexOf('\r', PosStart);
                    if(PosEnd != -1)
                    {
                        PosStart += 16;
                        string Length = m_Data.Substring(PosStart, PosEnd - PosStart);
                        m_BodyLen = int.Parse(Length);
                    }
                }
                else
                {
                    m_BodyLen = 0;
                }
                m_response.Header = m_Data.Substring(0, BodyStart);
        
            }
            if(BodyStart != -1)
                m_CurrBodyLen = m_Data.Length - BodyStart-4;
            else
                m_CurrBodyLen += data.Length;

            m_response.Body = m_Data.Substring(BodyStart, m_BodyLen);

            

            
        }
        private void Renegotiate(SSL.Client.SSLConnection conn)
        {
            conn.LoadNewClientCredentials(null);
        }
        private void HandShakeSuccess()
        {
            m_Connected = true;
        }
        private void ServerCertVerify(SSL.Common.Misc.CeriticateInfo ServCertInfo)
        {
            SSL.Common.Misc.ServerCertChainPolicyStatus Reason = ServCertInfo.PolStatus;
            byte[] CertData = ServCertInfo.CertData;
            
            if(CertData.Length > 0)
            {
                System.Security.Cryptography.X509Certificates.X509Certificate cert = new System.Security.Cryptography.X509Certificates.X509Certificate(CertData);
            }
        }
    }

}
