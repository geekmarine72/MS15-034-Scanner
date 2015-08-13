/**************************************************************************
   THIS CODE AND INFORMATION IS PROVIDED 'AS IS' WITHOUT WARRANTY OF
   ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO
   THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
   PARTICULAR PURPOSE.
   Author: Leon Finker  7/2002
**************************************************************************/
#include "StdAfx.h"
#include "sslserver.h"
#include <vcclr.h>

namespace SSL
{
namespace Server
{
    SSLServer::SSLServer(void)
    {
        try
        {
			m_pCS = __nogc new CRITICAL_SECTION();
            m_pSChannelCred = __nogc new SCHANNEL_CRED();
            m_phServerCreds = __nogc new CredHandle();
            m_pID2Clients = new CLIENTS_HM_TYPE();
        }
        catch(const std::bad_alloc&)
        {
            throw new OutOfMemoryException();
        }
		InitializeCriticalSection(m_pCS); 
        m_bAskClientForAuth = false;
        SecInvalidateHandle(m_phServerCreds);
        ZeroMemory(m_pSChannelCred, sizeof(SCHANNEL_CRED));
        m_pSecurityFunc = NULL;
        m_hSecurity = NULL;
        SecurityFunctionTable* pSecurityFunc = m_pSecurityFunc;
        if(!LoadSecurityLibrary(m_hSecurity, pSecurityFunc))
            throw new Common::Exceptions::SSLException(S"Failed to load security dll.");
        m_pSecurityFunc = pSecurityFunc;
    }
    bool SSLServer::SSPINegotiateLoop(void* IoBuffer, int& ActualLen, SecBuffer *pExtraData, Guid ClientID, Object* state)
    {
        TimeStamp            tsExpiry;
        CAutoSecBuffer<2>    InBuffer(m_pSecurityFunc, false);
        CAutoSecBuffer<1>    OutBuffer(m_pSecurityFunc, true);
        DWORD dwSSPIOutFlags;
        DWORD dwSSPIFlags = ASC_REQ_SEQUENCE_DETECT |
                            ASC_REQ_REPLAY_DETECT   |
                            ASC_REQ_CONFIDENTIALITY |
                            ASC_REQ_EXTENDED_ERROR  |
                            ASC_REQ_ALLOCATE_MEMORY |
                            ASC_REQ_STREAM;

        CLIENTDATA* pClientData;
        GetClientIDAssoc(ClientID, pClientData);
        if(m_bAskClientForAuth)
        {
            dwSSPIFlags |= ASC_REQ_MUTUAL_AUTH;
        }

        SECURITY_STATUS scRet = SEC_I_CONTINUE_NEEDED;

        while( scRet == SEC_I_CONTINUE_NEEDED) 
        {
            //
            // InBuffers[1] is for getting extra data that
            //  SSPI/SCHANNEL doesn't proccess on this
            //  run around the loop.
            //            
            InBuffer.SetSecurityBufferToken(0, IoBuffer, ActualLen);
            InBuffer.SetSecurityBufferEmpty(1);
            OutBuffer.SetSecurityBufferToken(0, NULL, 0);

            scRet = m_pSecurityFunc->AcceptSecurityContext(
                            m_phServerCreds,
                            SecIsValidHandle(&(pClientData->hContext))?&(pClientData->hContext):NULL,
                            &InBuffer,
                            dwSSPIFlags,
                            SECURITY_NATIVE_DREP,
                            &pClientData->hContext,
                            &OutBuffer,
                            &dwSSPIOutFlags,
                            &tsExpiry);

            if(scRet == SEC_E_INCOMPLETE_MESSAGE)
            {
                //tell caller to save the buffer for later input
                return false;
            }
            if(scRet == SEC_E_OK || scRet == SEC_I_CONTINUE_NEEDED ||
                (FAILED(scRet) && (0 != (dwSSPIOutFlags & ISC_RET_EXTENDED_ERROR))))
            {
                if(OutBuffer[0].cbBuffer != 0 && OutBuffer[0].pvBuffer != NULL )
                {
                    bool bSent = DispatchSend(static_cast<const char*>(OutBuffer[0].pvBuffer), OutBuffer[0].cbBuffer, ClientID, state);
                    if(!bSent)
                    {
					    throw new Common::Exceptions::SSLSendException(S"Send to Server failed.");
                    }
                    OutBuffer.FreeBuffer(0);
                }
            }
            if ( scRet == SEC_E_OK )
            {
                // leftover data
                // If the "extra" buffer contains data, this is encrypted application
                // protocol layer stuff. It needs to be saved. The application layer
                // will later decrypt it with DecryptMessage.
                //
                if(InBuffer[1].BufferType == SECBUFFER_EXTRA)
                {
                    pExtraData->pvBuffer = malloc(InBuffer[1].cbBuffer);
                    if(pExtraData->pvBuffer == NULL)
                    {
                        throw new OutOfMemoryException();
                    }

                    MoveMemory(pExtraData->pvBuffer,(BYTE*)IoBuffer + (ActualLen - InBuffer[1].cbBuffer),InBuffer[1].cbBuffer);

                    pExtraData->cbBuffer   = InBuffer[1].cbBuffer;
                    pExtraData->BufferType = SECBUFFER_TOKEN;
                }
                else
                {
                    pExtraData->pvBuffer   = NULL;
                    pExtraData->cbBuffer   = 0;
                    pExtraData->BufferType = SECBUFFER_EMPTY;
                }
                pClientData->bInHandShakeLoop = false;
                if(DoClientCertVerify != NULL)
                {
                    Common::Misc::CeriticateInfo ServCerInfo;
                    VerifyCertificate(false, m_pSecurityFunc,&(pClientData->hContext), NULL, 0, &ServCerInfo);
                        DoClientCertVerify(ServCerInfo);
                }
                if(DoHandShakeSuccess != NULL)
                {
                    DoHandShakeSuccess(ClientID);
                }
                break;
            }
            else if(FAILED(scRet))
            {
               throw new Common::Exceptions::SSLException(S"HandShake with the server failed. Error: ", scRet);
            }

            if ( InBuffer[1].BufferType == SECBUFFER_EXTRA )
            {
                MoveMemory(IoBuffer,(BYTE*)IoBuffer + (ActualLen - InBuffer[1].cbBuffer),InBuffer[1].cbBuffer);
                ActualLen = InBuffer[1].cbBuffer;
            }
            else if(scRet == SEC_I_CONTINUE_NEEDED)
            {
                ActualLen = 0;
                break;
            }
            else
            {
                //should not happen
                //throw new Common::Exceptions::SSLException(S"Unexpected condition. Error: ", scRet);
            }
        }
        return true;
    }
    
    void SSLServer::DisconnectFromClient(Guid ClientID, Object* state)
    {
        DWORD dwType = SCHANNEL_SHUTDOWN;
        CAutoSecBuffer<1> OutBuffer(m_pSecurityFunc, false);
        OutBuffer.SetSecurityBufferToken(0, &dwType, sizeof(dwType));

        CLIENTDATA* pClientData;
        GetClientIDAssoc(ClientID, pClientData);
        SECURITY_STATUS Status = m_pSecurityFunc->ApplyControlToken(&(pClientData->hContext), &OutBuffer);

        if(FAILED(Status)) 
        {
            RemoveClient(ClientID);
            throw new Common::Exceptions::SSLException(S"Disconnect failed. Error: ", Status);
        }

        DWORD dwSSPIFlags = ASC_REQ_SEQUENCE_DETECT |
                            ASC_REQ_REPLAY_DETECT   |
                            ASC_REQ_CONFIDENTIALITY |
                            ASC_REQ_EXTENDED_ERROR  |
                            ASC_REQ_ALLOCATE_MEMORY |
                            ASC_REQ_STREAM;

        OutBuffer.SetSecurityBufferToken(0, NULL, 0);
        
        DWORD     dwSSPIOutFlags;
        TimeStamp tsExpiry;
        Status = m_pSecurityFunc->AcceptSecurityContext(
                        m_phServerCreds,
                        &(pClientData->hContext),
                        NULL,
                        dwSSPIFlags,
                        SECURITY_NATIVE_DREP,
                        NULL,
                        &OutBuffer,
                        &dwSSPIOutFlags,
                        &tsExpiry);

        if(FAILED(Status)) 
        {
            RemoveClient(ClientID);
            throw new Common::Exceptions::SSLException("Failed to InitializeSecurityContext while shutting down.");      
        }

        char* pbMessage = static_cast<char*>(OutBuffer[0].pvBuffer);
        DWORD cbMessage = OutBuffer[0].cbBuffer;

        if(pbMessage != NULL && cbMessage != 0)
        {
            bool bRead = DispatchSend(pbMessage, cbMessage, ClientID, state);
            if(!bRead)
            {
                throw new Common::Exceptions::SSLSendException(S"Send to Server failed.");
            }
            m_pSecurityFunc->FreeContextBuffer(pbMessage);
        }
        RemoveClient(ClientID);
    }
    void SSLServer::EncryptSend(Byte data[], int ActualLen, Guid ClientID, Object* state)
    {
        CLIENTDATA* pClientData;
        GetClientIDAssoc(ClientID, pClientData);
        SecPkgContext_StreamSizes Sizes;
	    int IoBufferLength = GetMaxChunkSize(Sizes, ClientID);
        IoBufferLength += Sizes.cbHeader + Sizes.cbTrailer;
#ifdef _DEBUG
        if(GetMaxChunkSize(Sizes, ClientID) < (DWORD)data->Length)
            throw new Common::Exceptions::SSLException("Specified chunk size is invalid.");
#endif

        CAutoSecBuffer<4> Buffers(m_pSecurityFunc, false);
    	
		char* pbIoBuffer = (char*)malloc(IoBufferLength);
        if(pbIoBuffer == NULL)
            throw new OutOfMemoryException();
        
        Marshal::Copy(data, 0, pbIoBuffer + Sizes.cbHeader, ActualLen);

        Buffers.SetSecurityBufferStreamHeader(0, pbIoBuffer, Sizes.cbHeader);
        Buffers.SetSecurityBufferData(1, pbIoBuffer + Sizes.cbHeader, ActualLen);
        Buffers.SetSecurityBufferStreamTrailer(2, pbIoBuffer + Sizes.cbHeader + ActualLen, Sizes.cbTrailer);
        Buffers.SetSecurityBufferEmpty(3);
        SECURITY_STATUS scRet = m_pSecurityFunc->EncryptMessage(&(pClientData->hContext), 0, &Buffers, 0);

		if(FAILED(scRet) && scRet != SEC_E_CONTEXT_EXPIRED)
		{
            free(pbIoBuffer);
		    throw new Common::Exceptions::SSLException(S"EncryptMessage failed. Error: ", scRet);
		}

		int OutBufferLen = Buffers[0].cbBuffer+Buffers[1].cbBuffer+Buffers[2].cbBuffer;

        if(!DispatchSend(static_cast<char*>(pbIoBuffer), OutBufferLen, ClientID, state))
        {
            free(pbIoBuffer);
            throw new Common::Exceptions::SSLSendException(S"Send failed. Error: ", scRet);            
        }
        free(pbIoBuffer);
    }

    void SSLServer::DecryptData(Byte data[], Int32 ActualLen, Guid ClientID, Object* state)
    {
        CLIENTDATA* pClientData=NULL;
        try
        {
            //is it in map?
            GetClientIDAssoc(ClientID, pClientData);
        }
        catch(Common::Exceptions::SSLServerFailedToFindExistingClientID*)
        {
            //new client, init the needed data for new connection
            pClientData = new CLIENTDATA(m_pSecurityFunc);
            String* sClientID = ClientID.ToString();
            const wchar_t __pin* pClientID = PtrToStringChars(sClientID);
            try
            {
				EnterCriticalSection(m_pCS);
                (*m_pID2Clients)[pClientID] = pClientData;
				LeaveCriticalSection(m_pCS);
            }
            catch(const std::bad_alloc&)
            {
				LeaveCriticalSection(m_pCS);
                throw new OutOfMemoryException();
            }
        }
        //add previous leftover buffer
        ActualLen += pClientData->secExtraBuffer.cbBuffer;
        BYTE* pReadBuff = (BYTE*)malloc(ActualLen);
        if(pReadBuff == NULL)
            new OutOfMemoryException();
        //copy from managed to unmanaged, at position after extra data if any
        Marshal::Copy(data, 0, pReadBuff+pClientData->secExtraBuffer.cbBuffer, ActualLen-pClientData->secExtraBuffer.cbBuffer);
        if(pClientData->secExtraBuffer.cbBuffer > 0)
        {
            //copy from previous leftover data to beginning/before new one
            MoveMemory(pReadBuff, pClientData->secExtraBuffer.pvBuffer, pClientData->secExtraBuffer.cbBuffer);
            free(pClientData->secExtraBuffer.pvBuffer);
            pClientData->secExtraBuffer.cbBuffer = 0;
            pClientData->secExtraBuffer.pvBuffer = NULL;
        }
        SecBuffer ExtraBuffer={0};
        if(pClientData->bInHandShakeLoop)
        {
            if(!SSPINegotiateLoop(pReadBuff, ActualLen, &ExtraBuffer, ClientID, state))
            {
                // The input buffer contains only a fragment of an
                // encrypted record. Save the fragment and wait for more data.
                pClientData->secExtraBuffer.pvBuffer = pReadBuff;
                pClientData->secExtraBuffer.cbBuffer = ActualLen;
                return;
            }
            if(ExtraBuffer.cbBuffer == 0)
            {
                free(pReadBuff);
                return;
            }
            else if(ExtraBuffer.pvBuffer)
            {
               //save extra data and send it to decryptmessage
               MoveMemory(pReadBuff, ExtraBuffer.pvBuffer, ExtraBuffer.cbBuffer);
               ActualLen = ExtraBuffer.cbBuffer;
               free(ExtraBuffer.pvBuffer);
               ExtraBuffer.pvBuffer = NULL;
               ExtraBuffer.cbBuffer =0;
            }
        }
        
        while(true)
        {
            CAutoSecBuffer<4> Buffers(m_pSecurityFunc, false);
            Buffers.SetSecurityBufferData(0, pReadBuff, ActualLen);
            Buffers.SetSecurityBufferEmpty(1);
            Buffers.SetSecurityBufferEmpty(2);
            Buffers.SetSecurityBufferEmpty(3);
            CLIENTDATA* pClientData;
            GetClientIDAssoc(ClientID, pClientData);
            SECURITY_STATUS scRet = m_pSecurityFunc->DecryptMessage(&(pClientData->hContext), &Buffers, 0, NULL);

            if(scRet == SEC_E_INCOMPLETE_MESSAGE)
            {
                // The input buffer contains only a fragment of an
                // encrypted data. Save the fragment and wait for more data.
                pClientData->secExtraBuffer.pvBuffer = pReadBuff;
                pClientData->secExtraBuffer.cbBuffer = ActualLen;
                //pReadBuff is freed on next entry
                return;
            }
            if( scRet != SEC_E_OK && 
                scRet != SEC_I_RENEGOTIATE && 
                scRet != SEC_I_CONTEXT_EXPIRED)
            {
                free(pReadBuff);
                throw new Common::Exceptions::SSLException("Decryption Failed. Error: ", scRet);
            }

            // Client signalled end of session
            if(scRet == SEC_I_CONTEXT_EXPIRED)
		    {
                //pass in empty buffers and send output to remote as per specs
                EncryptSend(new Byte[0], 0, ClientID, state);
                free(pReadBuff);
                //Dispose();
                RemoveClient(ClientID);
                throw new Common::Exceptions::SSLException("Decryption Failed. Context Expired.");
		    }

            // Locate data and (optional) extra buffers.
		    SecBuffer* pDataBuffer = NULL;
		    SecBuffer* pExtraBuffer=NULL;
            for(int i = 1; i < 4; i++)
            {
                if(pDataBuffer == NULL && Buffers[i].BufferType == SECBUFFER_DATA)
                {
                    pDataBuffer = &Buffers[i];
                }
                if(pExtraBuffer == NULL && Buffers[i].BufferType == SECBUFFER_EXTRA)
                {
                    pExtraBuffer = &Buffers[i];
                }
            }

            // Display or otherwise process the decrypted data.
            if(pDataBuffer && pDataBuffer->cbBuffer > 0)
            {
                DispatchPlainData(pDataBuffer->pvBuffer, pDataBuffer->cbBuffer, ClientID, state);
            }

            // Move any "extra" data to the input buffer, update len and go around again
            if(pExtraBuffer != NULL)
            {
                MoveMemory(pReadBuff, pExtraBuffer->pvBuffer, pExtraBuffer->cbBuffer);
                ActualLen = pExtraBuffer->cbBuffer;
            }
            else if(scRet == S_OK)
                    break;
            if(scRet == SEC_I_RENEGOTIATE)
            {
                // The client wants to perform another handshake
                // sequence.
                pClientData->bInHandShakeLoop=true;
                int dummy =0;
                if(pExtraBuffer != NULL)
                    SSPINegotiateLoop(pReadBuff, ActualLen, &ExtraBuffer, ClientID, state);
                else
                    SSPINegotiateLoop(NULL, dummy, &ExtraBuffer, ClientID, state);
                // Move any "extra" data to the input buffer.
                if(ExtraBuffer.pvBuffer != NULL)
                {
                    MoveMemory(pReadBuff, ExtraBuffer.pvBuffer, ExtraBuffer.cbBuffer);
                    ActualLen = ExtraBuffer.cbBuffer;
                    free(ExtraBuffer.pvBuffer);
                    ExtraBuffer.pvBuffer = NULL;
                    ExtraBuffer.cbBuffer =0;
                }
                else
                    break;
            }
        }
	    free(pReadBuff);
    }    
    void SSLServer::DispatchPlainData(void* pData, long Len, Guid ClientID, Object* state)
    {
        Byte data[] = new Byte[Len];
        Marshal::Copy(IntPtr(pData), data, 0, Len);
        DoPlainData(data, ClientID, state);
    }
    bool SSLServer::DispatchSend(const char* pbMessage, DWORD cbMessage, Guid ClientID, Object* state)
    {
        Byte data[] = new Byte[cbMessage];
        Marshal::Copy(IntPtr((void*)pbMessage), data, 0, cbMessage);
        return DoWrite(data,ClientID, state);
    }
    DWORD SSLServer::GetMaxChunkSize(SecPkgContext_StreamSizes& Sizes, Guid ClientID)
    {
        CLIENTDATA* pClientData;
        GetClientIDAssoc(ClientID, pClientData);
        SECURITY_STATUS scRet = m_pSecurityFunc->QueryContextAttributesA(&(pClientData->hContext),SECPKG_ATTR_STREAM_SIZES,&Sizes);
        if(scRet != SEC_E_OK)
        {
            throw new Common::Exceptions::SSLException(S"Getting Maximum SSL chunk size failed. Error: ", scRet);
        }
        return Sizes.cbMaximumMessage;
    }   
    void SSLServer::SetupCredentials(Byte thumbPrint[], Common::Misc::SecurityProviderProtocol prot)
    {
        TimeStamp       tsExpiry;
        SECURITY_STATUS Status;
        HCERTSTORE      hCertStore;
        PCCERT_CONTEXT  pCertContext = NULL;

        // Open the "MY" certificate store, which is where Internet Explorer
        // stores its client certificates.
        hCertStore = CertOpenSystemStore(0, _T("MY"));
        if(hCertStore == NULL)
        {
           throw new Common::Exceptions::SSLException(String::Concat(S"Failed to open MY Certificate store. Error: ", Convert::ToString((unsigned int)GetLastError())));
        }
        if(thumbPrint != NULL && thumbPrint->Length > 0)
        {
            int HashLen = thumbPrint->Length;
            BYTE* pbData = (BYTE*)malloc(HashLen);
            Marshal::Copy(thumbPrint, 0, pbData, HashLen);
            CRYPT_HASH_BLOB hash={HashLen, pbData};
            SetLastError(0);
            pCertContext = CertFindCertificateInStore(hCertStore,X509_ASN_ENCODING, 
                                                    0,CERT_FIND_HASH,&hash,NULL);
            free(pbData);
            Status = GetLastError();
            if(pCertContext == NULL)
            {
                CertCloseStore(hCertStore, 0);
                hCertStore = NULL;
                throw new Common::Exceptions::SSLException(String::Concat(S"Failed to match certificate info. Error: ", Convert::ToString((unsigned int)Status)));
            }
        }        
        m_pSChannelCred->dwVersion  = SCHANNEL_CRED_VERSION;
        if(pCertContext != NULL)
        {
            m_pSChannelCred->cCreds     = 1;
            m_pSChannelCred->paCred     = &pCertContext;
        }
        m_pSChannelCred->grbitEnabledProtocols = prot;
        m_pSChannelCred->dwFlags = 0;
        
        Status = m_pSecurityFunc->AcquireCredentialsHandleA( NULL,                   // Name of principal    
									        UNISP_NAME_A,           // Name of package
									        SECPKG_CRED_INBOUND,   // Flags indicating use
									        NULL,                   // Pointer to logon ID
									        m_pSChannelCred,        // Package specific data
									        NULL,                   // Pointer to GetKey() func
									        NULL,                   // Value to pass to GetKey()
                                            m_phServerCreds,        // (out) Cred Handle
									        &tsExpiry);             // (out) Lifetime (optional)        
        if(Status != SEC_E_OK)
        {
            if(pCertContext != NULL)
            {
                CertCloseStore(hCertStore, 0);
                hCertStore = NULL;
                CertFreeCertificateContext(pCertContext);
            }
            throw new Common::Exceptions::SSLException(String::Concat(S"Failed to Acquire Credentials. Error: ", Convert::ToString((int)Status)));
        }
        //
        // Free the certificate context. Schannel has already made its own copy.
        //
        if(pCertContext != NULL)
        {
            CertCloseStore(hCertStore, 0);
            CertFreeCertificateContext(pCertContext);
            pCertContext = NULL;
        }
    }
    void SSLServer::GetClientIDAssoc(Guid ClientID, CLIENTDATA __nogc*& pClientData)
    {
        String* sClientID = ClientID.ToString();
        const wchar_t __pin* pClientID = PtrToStringChars(sClientID);
		EnterCriticalSection(m_pCS);
        CLIENTS_HM_TYPE::iterator iter = m_pID2Clients->find(std::wstring(pClientID));
        if(iter != m_pID2Clients->end())
        {
            pClientData = iter->second;
        }
        else
        {
			LeaveCriticalSection(m_pCS);
			throw new Common::Exceptions::SSLServerFailedToFindExistingClientID("SSL Server failed to find existing client id");
        }
		LeaveCriticalSection(m_pCS);
    }
    void SSLServer::RemoveClient(Guid ClientID)
    {
        String* sClientID = ClientID.ToString();
        const wchar_t __pin* pClientID = PtrToStringChars(sClientID);
		EnterCriticalSection(m_pCS);
        CLIENTS_HM_TYPE::iterator iter = m_pID2Clients->find(pClientID);
        if(iter != m_pID2Clients->end())
        {
            delete iter->second;
            iter->second = NULL;
            m_pID2Clients->erase(pClientID);
        }
		LeaveCriticalSection(m_pCS);
    }
    
    void SSLServer::AskForRenegotiate(Guid ClientID, Object* state)
    {
        CLIENTDATA* pClientData;
        GetClientIDAssoc(ClientID, pClientData);     
        CAutoSecBuffer<1> OutBuffer(m_pSecurityFunc, true);
        OutBuffer.SetSecurityBufferToken(0, NULL, 0);
        DWORD dwSSPIOutFlags;
        DWORD dwSSPIFlags = ASC_REQ_SEQUENCE_DETECT |
                            ASC_REQ_REPLAY_DETECT   |
                            ASC_REQ_CONFIDENTIALITY |
                            ASC_REQ_EXTENDED_ERROR  |
                            ASC_REQ_ALLOCATE_MEMORY |
                            ASC_REQ_STREAM          |
                            ASC_REQ_MUTUAL_AUTH;

        SECURITY_STATUS scRet = m_pSecurityFunc->AcceptSecurityContext(
                                                 m_phServerCreds, 
                                                 &(pClientData->hContext),
                                                 NULL, 
                                                 dwSSPIFlags, SECURITY_NATIVE_DREP,
                                                 &(pClientData->hContext),
                                                 &OutBuffer, &dwSSPIOutFlags, NULL);

       if(scRet != SEC_E_OK)
           throw new Common::Exceptions::SSLException(S"Renegotiate request failed. Error: ", scRet);
       if(OutBuffer[0].cbBuffer > 0 && OutBuffer[0].pvBuffer != NULL)
       {
            bool bSent = DispatchSend(static_cast<const char*>(OutBuffer[0].pvBuffer), OutBuffer[0].cbBuffer, ClientID, state);
            if(!bSent)
            {
                throw new Common::Exceptions::SSLSendException(S"Send to Server failed.");
            }
       }
    }

    void SSLServer::Dispose(bool disposing)
    {
		if(m_pCS != NULL)
		{
			DeleteCriticalSection(m_pCS);
			delete m_pCS;
			m_pCS = NULL;
		}
        if(SecIsValidHandle(m_phServerCreds))
        {
            m_pSecurityFunc->FreeCredentialsHandle(m_phServerCreds);
            SecInvalidateHandle(m_phServerCreds);
        }
        delete m_pSChannelCred;
        delete m_phServerCreds;
        m_pSChannelCred = NULL;
        m_phServerCreds = NULL;
        if(m_pSecurityFunc != NULL)
        {
            FreeLibrary(m_hSecurity);
            m_hSecurity = NULL;
            m_pSecurityFunc = NULL;
        }
		//not locking here, assumed that this is the end
        if(m_pID2Clients != NULL)
        {
            CLIENTS_HM_TYPE::iterator iter = m_pID2Clients->begin();
            for(; iter != m_pID2Clients->end(); iter++)
            {
                delete iter->second;
                iter->second = NULL;
            }
            m_pID2Clients->erase(m_pID2Clients->begin(), m_pID2Clients->end());
            delete m_pID2Clients;
            m_pID2Clients = NULL;
        }
		
    }
}
}