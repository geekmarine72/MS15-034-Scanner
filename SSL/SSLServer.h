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
    namespace Server
    {
        //write given data out
        public __delegate bool WriteSSL(Byte data[], Guid ClientID, Object* state);
        //process decrypted data
        public __delegate void PlainData(Byte data[], Guid ClientID, Object* state);
        //client's certificate information, optional
        public __delegate void VerifyClientCert(Common::Misc::CeriticateInfo ClientCertInfo);
        //handshake with client is successful
        public __delegate void HandShakeSuccess(Guid ClientID);

        __sealed public __gc class SSLServer : public IDisposable
        {
        public:
            SSLServer();
            ~SSLServer(){Dispose(false);}
        public:
            //disconnect from given client, based on id
            void DisconnectFromClient(Guid ClientID, Object* state);
            //clean up
            void Dispose() { Dispose(true); GC::SuppressFinalize(this);}
            //encrypt data, encrypted data is retuned in WriteSSL callback
            void EncryptSend(Byte data[], int ActualLen, Guid ClientID, Object* state);
            //decrypt data, decrypted data is returned in PlainData callback
            void DecryptData(Byte data[], Int32 ActualLen, Guid ClientID, Object* state);
            //remove client based on id from internal list of clients
            void RemoveClient(Guid ClientID);
            //maximum data chunk to use for send/recv at a time
            int MaxDataChunkSize(Guid ClientID)
            {
                SecPkgContext_StreamSizes notused; return GetMaxChunkSize(notused, ClientID);
            }
            //setup credentials, certThumbPrint is certificate's hash
            void SetupCredentials(Byte certThumbPrint[], Common::Misc::SecurityProviderProtocol prot);
            //ask client to renegotiate and possibly get different credentials
            void AskForRenegotiate(Guid ClientID, Object* state);
        public:
            //recommended initial chunk size when negotiation just starts, this is max auth token size
            __property int get_MaxInitialChunkSize()
            {
                PSecPkgInfo psecInfo;
                SECURITY_STATUS scRet = QuerySecurityPackageInfo(UNISP_NAME, &psecInfo);
                if (scRet != SEC_E_OK)
                    throw new Common::Exceptions::SSLException(S"Getting Maximum SSL token size failed. Error: ", scRet);
                return psecInfo->cbMaxToken;        
            }
            //ask client to provide certificate or not
            __property void set_AskClientForAuth(bool value)
            {
                m_bAskClientForAuth = value;
            }
        public:
            //callback for encrypted data
            WriteSSL* DoWrite;
            //callback for decrypted data
            PlainData*  DoPlainData;
            //optional
            VerifyClientCert* DoClientCertVerify;
            //optional
            HandShakeSuccess* DoHandShakeSuccess;
        ///////////////////////////////////////////////////////////////////
        private:
            bool SSPINegotiateLoop(void*, int&, SecBuffer*, Guid, Object*);
            bool DispatchSend(const char*, DWORD, Guid, Object*);
            void DispatchPlainData(void*, long, Guid, Object*);
            DWORD GetMaxChunkSize(SecPkgContext_StreamSizes&, Guid);
            void Dispose(bool disposing);
        private:
            __nogc struct CLIENTDATA
            {
                CtxtHandle hContext;
                SecBuffer  secExtraBuffer;
                bool       bInHandShakeLoop;
                SecurityFunctionTable __nogc* pSecurityFunc;
                CLIENTDATA(SecurityFunctionTable __nogc* pSecFunc):bInHandShakeLoop(true),pSecurityFunc(pSecFunc)
                {
                    SecInvalidateHandle(&hContext); 
                    secExtraBuffer.BufferType = -1;
                    secExtraBuffer.cbBuffer = 0;
                    secExtraBuffer.pvBuffer = NULL;
                }
                ~CLIENTDATA()
                {
                    if(secExtraBuffer.cbBuffer > 0)
                    {
                        free(secExtraBuffer.pvBuffer);
                        secExtraBuffer.cbBuffer = 0;
                        secExtraBuffer.pvBuffer = NULL;
                    }
                    
                    pSecurityFunc->DeleteSecurityContext(&hContext);
                    SecInvalidateHandle(&hContext);
                }
            };
        private:
            void GetClientIDAssoc(Guid, CLIENTDATA __nogc*&);
        private:
			CRITICAL_SECTION __nogc* m_pCS;
            SCHANNEL_CRED __nogc*    m_pSChannelCred;
            CredHandle __nogc*		 m_phServerCreds;
            SecurityFunctionTable __nogc* m_pSecurityFunc;
            HMODULE m_hSecurity;
            //typedef std::hash_map<std::wstring, CLIENTDATA __nogc*, WStringComp> CLIENTS_HM_TYPE;
            typedef std::map<std::wstring, CLIENTDATA __nogc*, WStringComp> CLIENTS_HM_TYPE;
            CLIENTS_HM_TYPE __nogc* m_pID2Clients;
            bool m_bAskClientForAuth;
        };
    }
}