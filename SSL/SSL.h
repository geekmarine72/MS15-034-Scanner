// SSL.h
/**************************************************************************
   THIS CODE AND INFORMATION IS PROVIDED 'AS IS' WITHOUT WARRANTY OF
   ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO
   THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
   PARTICULAR PURPOSE.
   Author: Leon Finker  7/2002
**************************************************************************/
#pragma once
#include "sslcommon.h"

namespace SSL
{
    public __value struct ServerCeriticateInfo;
    namespace Client
    {
        //write given data out
        public __delegate bool WriteSSL(Byte data[], Object* state);
        //process decrypted data
        public __delegate void PlainData(Byte data[], Object* state);
        //server's certificate information, optional
        public __delegate void VerifyServCert(Common::Misc::CeriticateInfo ServCertInfo);
        //handshake with server is successful
        public __delegate void HandShakeSuccess();
        
        __sealed public __gc class SSLConnection;
        //server asked for renegotiation, load new certificate, such as SSLConn->LoadNewClientCredentials
        public __delegate void NewCertificate(SSLConnection* SSLConn);

        __sealed public __gc class SSLConnection : public IDisposable
	    {
        public:

            SSLConnection();
            ~SSLConnection()
            {
                Dispose(false);
            }
        public:
            //initiate connection, given server's ip and client's certificate hash,
            //data to be sent will be returned in WriteSSL callback
            void InitiateHandShake(String* ipAddress, Byte thumbPrint[], Common::Misc::SecurityProviderProtocol prot, Object* state);
            //encrypt data, encrypted data is retuned in WriteSSL callback
            void EncryptSend(Byte data[], int ActualLen, Object* state);
            //decrypt data, decrypted data is returned in PlainData callback
            void DecryptData(Byte data[], Int32 ActualSize, Object* state);
            //disconnect from server
            bool Disconnect(Object* state);
            //clean up
            void Dispose() { Dispose(true); GC::SuppressFinalize(this);}
            //load new client's credentials from NewCertificate callback
            void LoadNewClientCredentials(Byte sha1hash[]);
        public:        
            //maximum data chunk to use for send/recv at a time
            __property int get_MaxDataChunkSize()
            {
                SecPkgContext_StreamSizes notused; return GetMaxChunkSize(notused);
            }
            //recommended initial chunk size when negotiation just starts, this is max auth token size
            __property int get_MaxInitialChunkSize()
            {
                PSecPkgInfo psecInfo;
                SECURITY_STATUS scRet = QuerySecurityPackageInfo(UNISP_NAME, &psecInfo);
                if (scRet != SEC_E_OK)
                    throw new Common::Exceptions::SSLException(S"Getting Maximum SSL token size failed. Error: ", scRet);
                return psecInfo->cbMaxToken;
            }
        public:
            //callback for encrypted data
            WriteSSL*         DoWrite;
            //callback for decrypted data
            PlainData*        DoPlainData;
            //optional
            NewCertificate*   DoRenegotiate;
            //optional
            VerifyServCert*   DoServerCertVerify;
            //optional
            HandShakeSuccess* DoHandShakeSuccess;
        ///////////////////////////////////////////////////////////////////////////
        private:
            void Init();
            void SetupCredentials(Byte[], Common::Misc::SecurityProviderProtocol);
            void PerformHandShake(Object* state);
            bool ClientHandshakeLoop(void*, int&, SecBuffer*, Object* state);
            bool DispatchSend(const char*, DWORD, Object* state);
            void DispatchPlainData(void*, long, Object* state);
            DWORD GetMaxChunkSize(SecPkgContext_StreamSizes&);
            void Dispose(bool);
        private:
            bool            m_bInHandShake;
            String*         m_ServerIP;
            int             m_Port;
            SCHANNEL_CRED __nogc*   m_pSChannelCred;
            CredHandle __nogc*		m_phClientCreds;
            CtxtHandle __nogc*		m_phContext;
            SecurityFunctionTable __nogc* m_pSecurityFunc;
            HMODULE   m_hSecurity;
            SecBuffer m_SecExtraBuffer;
	    };
    }
}
