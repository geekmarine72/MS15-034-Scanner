
// <copyright file="HTTPSocket.cs" company="McKesson / RelayHealth">
// Copyright (c) 2015 All Rights Reserved
// </copyright>
// <author>Paul Vilevac</author>
// <date>04/15/2015 10:31 AM PST</date>

namespace IIS_SCAN
{
    using System;
    using System.Linq;
    using System.Net;
    using System.Net.Sockets;
    using System.Text;
    using System.Text.RegularExpressions;



    /// <summary>
    /// A simplified wrapper which uses sockets to transmit and receive HTTP requests.
    /// </summary>
    /// <remarks>
    /// This class allows a simple get request to be posted to a web server on any specified port. 
    /// </remarks>
    public static class HTTPSocket
    {
        /// <summary>
        /// Simplified structure which holds the result of the get request
        /// </summary>
 

        /// <summary>
        /// Transmits an arbitrary string to a host on a given port.  It is assumed to be a valid HTTP request.
        /// </summary>
        /// <param name="address">An IPv4 Address to which the request will be sent.</param>
        /// <param name="port">A valid port on the target host which is listening for socket requests.</param>
        /// <param name="request">A string which shoul contain a valid HTTP request.  It is not validated</param>
        /// <returns>Response</returns>
        /// <seealso cref="Response"/>
        public static Response Get(IPEndPoint ipEndpoint, string request)
        {

            var result = new Response();

            var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);

            socket.Connect(ipEndpoint);

            
            socket.Send(Encoding.ASCII.GetBytes(request));

            bool flag = true;
            
            int contentLength = 0; 
            byte[] bodyBuff = new byte[0]; 
            while (flag)
            {
                // read the header byte by byte, until \r\n\r\n
                byte[] buffer = new byte[1];
                socket.Receive(buffer, 0, 1, 0);
                result.Header += Encoding.ASCII.GetString(buffer);
                if (result.Header.Contains("\r\n\r\n"))
                {
                    // header is received, parsing content length
                    // I use regular expressions, but any other method you can think of is ok
                    Regex reg = new Regex("\\\r\nContent-Length: (.*?)\\\r\n");
                    Match m = reg.Match(result.Header);
                    contentLength = int.Parse(m.Groups[1].ToString());
                    flag = false;
                    // read the body
                    bodyBuff = new byte[contentLength];
                    socket.Receive(bodyBuff, 0, contentLength, 0);
                }
            }

            result.Body = Encoding.ASCII.GetString(bodyBuff);
            
            socket.Close();

            return result;
        }
        
    }
}
