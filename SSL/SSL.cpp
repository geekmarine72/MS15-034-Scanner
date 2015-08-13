/**************************************************************************
   THIS CODE AND INFORMATION IS PROVIDED 'AS IS' WITHOUT WARRANTY OF
   ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO
   THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
   PARTICULAR PURPOSE.
   Author: Leon Finker  7/2002
**************************************************************************/
#include "stdafx.h"
#include "SSL.h"
#include <new>
namespace SSL
{
namespace Client
{
	SSLConnection::SSLConnection()
	{
		Init();
	}
	
	void SSLConnection::InitiateHandShake(String* ipAddres, Byte thumbPrint[], Common::Misc::SecurityProviderProtocol prot, Object* state)
	{
		if(m_ServerIP != NULL)
		{
			Dispose();
			Init();
		}
		m_ServerIP = ipAddres;
		try
		{
			SetupCredentials(thumbPrint, prot);
			PerformHandShake(state);
		}
		catch(Common::Exceptions::SSLException*)
		{
			Dispose();
			throw;
		}
	}

	void SSLConnection::PerformHandShake(Object* state)
	{
		DWORD           dwSSPIFlags;
		DWORD           dwSSPIOutFlags;
		TimeStamp       tsExpiry;
		SECURITY_STATUS scRet = S_OK;

		dwSSPIFlags = ISC_REQ_SEQUENCE_DETECT | ISC_REQ_REPLAY_DETECT   |
					  ISC_REQ_CONFIDENTIALITY | ISC_RET_EXTENDED_ERROR  |
					  ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_STREAM;
		//
		//  Initiate a ClientHello message and generate a token.
		//
		CAutoSecBuffer<1> OutBuffer(m_pSecurityFunc, true);
		OutBuffer.SetSecurityBufferToken(0, NULL, 0);
		
		IntPtr ptrServerName = System::Runtime::InteropServices::Marshal::StringToCoTaskMemAnsi(m_ServerIP);        
		scRet = m_pSecurityFunc->InitializeSecurityContextA( m_phClientCreds, NULL,
						static_cast<SEC_CHAR*>(ptrServerName.ToPointer()),
						dwSSPIFlags,0,
						SECURITY_NATIVE_DREP,
						NULL, 0, m_phContext, &OutBuffer,
						&dwSSPIOutFlags, &tsExpiry);
		System::Runtime::InteropServices::Marshal::FreeCoTaskMem(ptrServerName);

		if(scRet == SEC_I_INCOMPLETE_CREDENTIALS)
		{
			DoRenegotiate(this);
		}
		else if(scRet != SEC_I_CONTINUE_NEEDED)
		{
			throw new Common::Exceptions::SSLException(S"InitializeSecurityContext Failed. Error: ", scRet);
		}
		
		m_bInHandShake = true;

		// Send response to server if there is one.
		if(OutBuffer[0].cbBuffer != 0 && OutBuffer[0].pvBuffer != NULL)
		{
			bool bSent = DispatchSend(static_cast<char*>(OutBuffer[0].pvBuffer), OutBuffer[0].cbBuffer, state);
			if(!bSent)
			{
				throw new Common::Exceptions::SSLSendException(S"Send to Server failed.");
			}
		}
	}
	bool SSLConnection::ClientHandshakeLoop(void* IoBuffer, int& ActualLen, SecBuffer *pExtraData, Object* state)
	{
		CAutoSecBuffer<2> InBuffer(m_pSecurityFunc, false);
		CAutoSecBuffer<1> OutBuffer(m_pSecurityFunc, true);        
		
		TimeStamp tsExpiry;

		DWORD dwSSPIOutFlags;
		DWORD dwSSPIFlags = ISC_REQ_SEQUENCE_DETECT | ISC_REQ_REPLAY_DETECT |
								ISC_REQ_CONFIDENTIALITY | ISC_RET_EXTENDED_ERROR |
								ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_STREAM;
	   
		SECURITY_STATUS scRet = SEC_I_CONTINUE_NEEDED;

		while(scRet == SEC_I_CONTINUE_NEEDED || scRet == SEC_I_INCOMPLETE_CREDENTIALS) 
		{
			//
			// Set up the input buffers. Buffer 0 is used to pass in data
			// received from the server. Schannel will consume some or all
			// of this. Leftover data (if any) will be placed in buffer 1 and
			// given a buffer type of SECBUFFER_EXTRA.
			//
			
			InBuffer.SetSecurityBufferToken(0, IoBuffer, ActualLen);
			InBuffer.SetSecurityBufferEmpty(1);
			OutBuffer.SetSecurityBufferToken(0, NULL, 0);
			scRet = m_pSecurityFunc->InitializeSecurityContextA(m_phClientCreds,
											m_phContext,
											NULL,
											dwSSPIFlags,
											0,
											SECURITY_NATIVE_DREP,
											&InBuffer,
											0,
											NULL,
											&OutBuffer,
											&dwSSPIOutFlags,
											&tsExpiry);
			//
			// If InitializeSecurityContext was successful (or if the error was 
			// one of the special extended ones), send the contents of the output
			// buffer to the server.
			//

			if(scRet == SEC_E_OK || scRet == SEC_I_CONTINUE_NEEDED || (FAILED(scRet) 
			   && (dwSSPIOutFlags & ISC_RET_EXTENDED_ERROR)))
			{
				if(OutBuffer[0].cbBuffer != 0 && OutBuffer[0].pvBuffer != NULL)
				{
					bool bSent = DispatchSend(static_cast<char*>(OutBuffer[0].pvBuffer), OutBuffer[0].cbBuffer, state);
					if(!bSent)
					{
						throw new Common::Exceptions::SSLSendException(S"Send to Server failed.");
					}
				}
				OutBuffer.FreeBuffer(0);
			}
			//
			// If InitializeSecurityContext returned SEC_E_INCOMPLETE_MESSAGE,
			// then we need to read more data from the server and try again.
			//
			if(scRet == SEC_E_INCOMPLETE_MESSAGE)
			{
				//tell caller to save the buffer for later input
				return false;
			}
			//
			// If InitializeSecurityContext returned SEC_E_OK, then the 
			// handshake completed successfully.
			//
			if(scRet == SEC_E_OK)
			{
				//
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

				//
				// Bail out to quit
				//
				m_bInHandShake = false;
				if(DoServerCertVerify != NULL)
				{
					IntPtr ptrServerName = System::Runtime::InteropServices::Marshal::StringToCoTaskMemUni(m_ServerIP);
					Common::Misc::CeriticateInfo ServCertInfo;
					VerifyCertificate(true, m_pSecurityFunc, m_phContext, static_cast<wchar_t*>(ptrServerName.ToPointer()), 0, &ServCertInfo);
						DoServerCertVerify(ServCertInfo);
					System::Runtime::InteropServices::Marshal::FreeCoTaskMem(ptrServerName);
					DoServerCertVerify = NULL; //prevent other calls during renegotiation, etc.
				}
				if(DoHandShakeSuccess != NULL)
				{
					DoHandShakeSuccess();
				}
				break;
			}

			//
			// Check for fatal error.
			//

			if(FAILED(scRet))
			{
				throw new Common::Exceptions::SSLException(S"HandShake with the server failed. Error: ", scRet);
			}
			//
			// If InitializeSecurityContext returned SEC_I_INCOMPLETE_CREDENTIALS,
			// then the server just requested client authentication. 
			//
			if(scRet == SEC_I_INCOMPLETE_CREDENTIALS)
			{
				if(DoRenegotiate != NULL)
					DoRenegotiate(this); 
				SECURITY_STATUS scRet = SEC_I_CONTINUE_NEEDED;
				continue;
			}
			//
			// Copy any leftover data from the "extra" buffer, and go around
			// again.
			//
			if ( InBuffer[1].BufferType == SECBUFFER_EXTRA )
			{
				int temp = ActualLen;
				MoveMemory(IoBuffer,(BYTE*)IoBuffer + (ActualLen - InBuffer[1].cbBuffer),InBuffer[1].cbBuffer);
				ActualLen = InBuffer[1].cbBuffer;
			}
			else
			{
				ActualLen = 0;
				break;
			}
		}
		return true;
	}
	
	void SSLConnection::LoadNewClientCredentials(Byte certhash[])
	{
		CredHandle						hCreds;
		SecPkgContext_IssuerListInfoEx	IssuerListInfo;
		PCCERT_CHAIN_CONTEXT			pChainContext;
		CERT_CHAIN_FIND_BY_ISSUER_PARA	FindByIssuerPara;
		PCCERT_CONTEXT					pCertContext;
		TimeStamp						tsExpiry;
		SECURITY_STATUS					Status;
		HCERTSTORE                      hCertStore;
		//
		// Read list of trusted issuers from schannel.
		//
		Status = m_pSecurityFunc->QueryContextAttributesA(m_phContext,
										SECPKG_ATTR_ISSUER_LIST_EX,(PVOID)&IssuerListInfo);
		if(Status != SEC_E_OK)
		{
			throw new Common::Exceptions::SSLException(S"Acquiring new credentials failed. Error: ", Status);
		}
		//
		// Enumerate the client certificates.
		//
		ZeroMemory(&FindByIssuerPara, sizeof(FindByIssuerPara));
		FindByIssuerPara.cbSize = sizeof(FindByIssuerPara);
		FindByIssuerPara.pszUsageIdentifier = szOID_PKIX_KP_CLIENT_AUTH;
		FindByIssuerPara.dwKeySpec = 0;
		FindByIssuerPara.cIssuer   = IssuerListInfo.cIssuers;
		FindByIssuerPara.rgIssuer  = IssuerListInfo.aIssuers;
		pChainContext = NULL;
		hCertStore = CertOpenSystemStore(0, _T("MY"));
		if(hCertStore == NULL)
		{
			throw new Common::Exceptions::SSLException(String::Concat(S"Failed to open MY Certificate store. Error: ", Convert::ToString((unsigned int)GetLastError())));
		}
		while(TRUE)
		{
			// Find a certificate chain.
			pChainContext = CertFindChainInStore(hCertStore,
												X509_ASN_ENCODING,
												0,
												CERT_CHAIN_FIND_BY_ISSUER,
												&FindByIssuerPara,
												pChainContext);
			if(pChainContext == NULL)
			{
				break;
			}

			// Get pointer to leaf certificate context.
			pCertContext = pChainContext->rgpChain[0]->rgpElement[0]->pCertContext;
			
			// Create schannel credential.
			m_pSChannelCred->cCreds = 1;
			m_pSChannelCred->paCred = certhash == NULL? NULL:&pCertContext;
			DWORD dwLen =0;
			if(certhash != NULL && CertGetCertificateContextProperty(pCertContext, CERT_HASH_PROP_ID, NULL, &dwLen))
			{
			   if(dwLen != certhash->Length)
			   {
					continue;
			   }
			   void* pCertHash = malloc(dwLen);
			   if(pCertHash == NULL)
				   throw new OutOfMemoryException();
			   if(CertGetCertificateContextProperty(pCertContext, CERT_HASH_PROP_ID, pCertHash, &dwLen))
			   {
					void* pCertHashGiven =malloc(certhash->Length);
					if(pCertHashGiven == NULL)
					{
						free(pCertHash);
						throw new OutOfMemoryException();
					}
					Marshal::Copy(certhash, 0, pCertHashGiven, certhash->Length);
					if(memcmp(pCertHashGiven, pCertHash, certhash->Length) != 0)
					{
						free(pCertHashGiven);
						free(pCertHash);
						continue;
					}
					free(pCertHashGiven);
					free(pCertHash);
			   }
			   
			}
			
			Status = m_pSecurityFunc->AcquireCredentialsHandleA(
								NULL,                   // Name of principal
								UNISP_NAME_A,            // Name of package
								SECPKG_CRED_OUTBOUND,   // Flags indicating use
								NULL,                   // Pointer to logon ID
								m_pSChannelCred,          // Package specific data
								NULL,                   // Pointer to GetKey() func
								NULL,                   // Value to pass to GetKey()
								&hCreds,                // (out) Cred Handle
								&tsExpiry);             // (out) Lifetime (optional)
			if(Status != SEC_E_OK)
			{
				continue;
			}
			// Destroy the old credentials.
			CertFreeCertificateChain(pChainContext);
			m_pSecurityFunc->FreeCredentialsHandle(m_phClientCreds);
			*m_phClientCreds = hCreds;
			break;
		}
		CertCloseStore(hCertStore, 0);
		hCertStore = NULL;
	}
	DWORD SSLConnection::GetMaxChunkSize(SecPkgContext_StreamSizes& Sizes)
	{
		SECURITY_STATUS scRet = m_pSecurityFunc->QueryContextAttributesA(m_phContext,SECPKG_ATTR_STREAM_SIZES,&Sizes);
		if(scRet != SEC_E_OK)
		{
			throw new Common::Exceptions::SSLException(S"Getting Maximum SSL chunk size failed. Error: ", scRet);
		}
		return Sizes.cbMaximumMessage;
	}
	bool SSLConnection::Disconnect(Object* state)
	{
		//
		// Notify schannel that we are about to close the connection.
		//

		DWORD dwType = SCHANNEL_SHUTDOWN;
		CAutoSecBuffer<1> OutBuffer(m_pSecurityFunc, false);
		OutBuffer.SetSecurityBufferToken(0, &dwType, sizeof(dwType));

		SECURITY_STATUS Status = m_pSecurityFunc->ApplyControlToken(m_phContext, &OutBuffer);

		if(FAILED(Status))
		{
			throw new Common::Exceptions::SSLException(S"Disconnect failed. Error: ", Status);
		}
		//
		// Build an SSL close notify message.
		//
		DWORD dwSSPIFlags = ISC_REQ_SEQUENCE_DETECT   |
							ISC_REQ_REPLAY_DETECT     |
							ISC_REQ_CONFIDENTIALITY   |
							ISC_RET_EXTENDED_ERROR    |
							ISC_REQ_ALLOCATE_MEMORY   |
							ISC_REQ_STREAM;

		OutBuffer.SetSecurityBufferToken(0, NULL, 0);
		TimeStamp tsExpiry;
		DWORD     dwSSPIOutFlags;
		Status = m_pSecurityFunc->InitializeSecurityContextA(
						m_phClientCreds,
						m_phContext,
						NULL,
						dwSSPIFlags,
						0,
						SECURITY_NATIVE_DREP,
						NULL,
						0,
						m_phContext,
						&OutBuffer,
						&dwSSPIOutFlags,
						&tsExpiry);

		if(FAILED(Status)) 
		{
			throw new Common::Exceptions::SSLException("Failed to InitializeSecurityContext while shutting down.");
		}

		char* pbMessage = static_cast<char*>(OutBuffer[0].pvBuffer);
		DWORD cbMessage = OutBuffer[0].cbBuffer;
		//
		// Send the close notify message to the server.
		//
		if(pbMessage != NULL && cbMessage != 0)
		{
			bool bRead = DispatchSend(pbMessage, cbMessage, state);
			if(!bRead)
			{
				throw new Common::Exceptions::SSLSendException(S"Send to Server failed.");
			}

			// Free output buffer.
			m_pSecurityFunc->FreeContextBuffer(pbMessage);
		}
		
		if(SecIsValidHandle(m_phContext))
		{
			Dispose();
		}
		return true;
	}

	void SSLConnection::EncryptSend(Byte data[], int ActualLen, Object* state)
	{
		SecPkgContext_StreamSizes Sizes;
		int IoBufferLength = GetMaxChunkSize(Sizes);
		IoBufferLength += Sizes.cbHeader + Sizes.cbTrailer;
#ifdef _DEBUG
		if(GetMaxChunkSize(Sizes) < (DWORD)ActualLen)
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

		SECURITY_STATUS scRet = m_pSecurityFunc->EncryptMessage(m_phContext, 0, &Buffers, 0);

		if(FAILED(scRet) && scRet != SEC_E_CONTEXT_EXPIRED)
		{
			free(pbIoBuffer);
			throw new Common::Exceptions::SSLException(S"EncryptMessage failed. Error: ", scRet);
		}

		int OutBufferLen = Buffers[0].cbBuffer+Buffers[1].cbBuffer+Buffers[2].cbBuffer;

		if(!DispatchSend(static_cast<char*>(pbIoBuffer), OutBufferLen, state))
		{
			free(pbIoBuffer);
			throw new Common::Exceptions::SSLSendException(S"Send failed. Error: ", scRet);            
		}

		free(pbIoBuffer);
	}

	void SSLConnection::DecryptData(Byte data[], Int32 ActualLen, Object* state)
	{
		SecBuffer ExtraBuffer={0};
		//add previous leftover buffer
		ActualLen += m_SecExtraBuffer.cbBuffer;
		BYTE* pReadBuff = (BYTE*)malloc(ActualLen);
		if(pReadBuff == NULL)
			new OutOfMemoryException();
		//copy from managed to unmanaged, at position after extra data if any
		Marshal::Copy(data, 0, pReadBuff+m_SecExtraBuffer.cbBuffer, ActualLen-m_SecExtraBuffer.cbBuffer);
		if(m_SecExtraBuffer.cbBuffer > 0)
		{
			//copy from previous leftover data to beginning/before new one
			MoveMemory(pReadBuff, m_SecExtraBuffer.pvBuffer, m_SecExtraBuffer.cbBuffer);
			free(m_SecExtraBuffer.pvBuffer);
			m_SecExtraBuffer.cbBuffer = 0;
			m_SecExtraBuffer.pvBuffer = NULL;
		}
		if(m_bInHandShake)
		{
			if(!ClientHandshakeLoop(pReadBuff, ActualLen, &ExtraBuffer, state))
			{
				// The input buffer contains only a fragment of an
				// encrypted record. Save the fragment and wait for more data.
				m_SecExtraBuffer.pvBuffer = pReadBuff;
				m_SecExtraBuffer.cbBuffer = ActualLen;
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

			SECURITY_STATUS scRet = m_pSecurityFunc->DecryptMessage(m_phContext, &Buffers, 0, NULL);

			if(scRet == SEC_E_INCOMPLETE_MESSAGE)
			{
				// The input buffer contains only a fragment of an
				// encrypted data. Save the fragment and wait for more data.
				m_SecExtraBuffer.pvBuffer = pReadBuff;
				m_SecExtraBuffer.cbBuffer = ActualLen;
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

			// Server signalled end of session
			if(scRet == SEC_I_CONTEXT_EXPIRED)
			{
				//pass in empty buffers and send output to remote as per specs
				EncryptSend(new Byte[0], 0, state);
				Dispose();
				free(pReadBuff);
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
				DispatchPlainData(pDataBuffer->pvBuffer, pDataBuffer->cbBuffer, state);
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
				// The server wants to perform another handshake
				// sequence.
				DoRenegotiate(this);
				m_bInHandShake=true;
				int dummy =0;
				if(pExtraBuffer != NULL)
					ClientHandshakeLoop(pReadBuff, ActualLen, &ExtraBuffer, state);
				else
					ClientHandshakeLoop(NULL, dummy, &ExtraBuffer, state);
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

	bool SSLConnection::DispatchSend(const char* pbMessage, DWORD cbMessage, Object* state)
	{
		Byte data[] = new Byte[cbMessage];
		Marshal::Copy(IntPtr((void*)pbMessage), data, 0, cbMessage);
		return DoWrite(data, state);
	}
	void SSLConnection::DispatchPlainData(void* pData, long Len, Object* state)
	{
		Byte data[] = new Byte[Len];
		Marshal::Copy(IntPtr(pData), data, 0, Len);
		DoPlainData(data, state);
	}
	void SSLConnection::Init()
	{
		if(m_pSecurityFunc != NULL)
			return;
		m_SecExtraBuffer.BufferType = -1;
		m_SecExtraBuffer.cbBuffer = 0;
		m_SecExtraBuffer.pvBuffer = NULL;
		m_bInHandShake = false;
		try
		{
			m_pSChannelCred = __nogc new SCHANNEL_CRED();
			m_phClientCreds = __nogc new CredHandle();
			m_phContext     = __nogc new CtxtHandle();
		}
		catch(const std::bad_alloc&)
		{
			throw new OutOfMemoryException();
		}
		SecInvalidateHandle(m_phClientCreds);
		SecInvalidateHandle(m_phContext);    
		memset(m_pSChannelCred, 0, sizeof(SCHANNEL_CRED));
		m_pSecurityFunc = NULL;
		m_hSecurity = NULL;
		SecurityFunctionTable* pSecurityFunc = m_pSecurityFunc;
		if(!LoadSecurityLibrary(m_hSecurity, pSecurityFunc))
			throw new Common::Exceptions::SSLException(S"Failed to load security dll.");
		m_pSecurityFunc = pSecurityFunc;
		m_ServerIP = NULL;
	}
	
	void SSLConnection::SetupCredentials(Byte thumbPrint[], Common::Misc::SecurityProviderProtocol prot)
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
			pCertContext = CertFindCertificateInStore(hCertStore,
													X509_ASN_ENCODING, 
													0,
													CERT_FIND_HASH,
													&hash,
													NULL);
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
		m_pSChannelCred->dwFlags |= SCH_CRED_NO_DEFAULT_CREDS|SCH_CRED_MANUAL_CRED_VALIDATION;
		
		Status = m_pSecurityFunc->AcquireCredentialsHandleA( NULL,                   // Name of principal    
											UNISP_NAME_A,           // Name of package
											SECPKG_CRED_OUTBOUND,   // Flags indicating use
											NULL,                   // Pointer to logon ID
											m_pSChannelCred,        // Package specific data
											NULL,                   // Pointer to GetKey() func
											NULL,                   // Value to pass to GetKey()
											m_phClientCreds,        // (out) Cred Handle
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
	void SSLConnection::Dispose(bool disposing)
	{
		m_ServerIP = NULL;
		DoWrite=NULL;
		DoPlainData=NULL;
		DoRenegotiate=NULL;
		DoServerCertVerify=NULL;
		DoHandShakeSuccess=NULL;
		m_bInHandShake = false;
		if(m_SecExtraBuffer.cbBuffer > 0)
			free(m_SecExtraBuffer.pvBuffer);
		m_SecExtraBuffer.cbBuffer = 0;
		m_SecExtraBuffer.pvBuffer = NULL;

		if(SecIsValidHandle(m_phContext))
		{
			m_pSecurityFunc->DeleteSecurityContext(m_phContext);
			SecInvalidateHandle(m_phContext);
		}
		if(SecIsValidHandle(m_phClientCreds))
		{
			m_pSecurityFunc->FreeCredentialsHandle(m_phClientCreds);
			SecInvalidateHandle(m_phClientCreds);
		}

		if(!disposing)
		{
			delete m_pSChannelCred;
			delete m_phClientCreds;
			delete m_phContext;
			m_pSChannelCred = NULL;
			m_phClientCreds = NULL;
			m_phContext = NULL;
			if(m_hSecurity != NULL)
			{
				FreeLibrary(m_hSecurity);
				m_hSecurity = NULL;
				m_pSecurityFunc = NULL;
			}
		}
	}
}
}