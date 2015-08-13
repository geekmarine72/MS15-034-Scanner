/**************************************************************************
   THIS CODE AND INFORMATION IS PROVIDED 'AS IS' WITHOUT WARRANTY OF
   ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO
   THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
   PARTICULAR PURPOSE.
   Author: Leon Finker  7/2002
**************************************************************************/
#pragma once
#using <mscorlib.dll>
#include <windows.h>
#include <wincrypt.h>
#include <schannel.h>
#define SECURITY_WIN32
#include <security.h>
#include <sspi.h>
#include "tchar.h"

using namespace System;
using namespace System::Net;
using namespace System::Runtime::InteropServices;

#pragma comment(lib, "Crypt32")
#pragma comment(lib, "Secur32")

namespace SSL
{
namespace Common
{
    namespace Exceptions
    {
    [Serializable]
	public __gc class SSLException : public ApplicationException
    {
    public:
        SSLException(){}
        SSLException(String* message):ApplicationException(message){}
        SSLException(String* message, Exception* innerException)
            :ApplicationException(message,innerException){}
        SSLException(String* message, UInt32 error)
            :ApplicationException(String::Concat(message, Convert::ToString(error))){}

    };
    [Serializable]
    __sealed public __gc class SSLServerFailedToFindExistingClientID : public SSLException
    {
    public:
        SSLServerFailedToFindExistingClientID(){}
        SSLServerFailedToFindExistingClientID(String* message):SSLException(message){}
        SSLServerFailedToFindExistingClientID(String* message, Exception* innerException)
            :SSLException(message,innerException){}
    };
    [Serializable]
    __sealed public __gc class SSLServerDisconnectedException : public SSLException
    {
    public:
        SSLServerDisconnectedException(){}
        SSLServerDisconnectedException(String* message):SSLException(message){}
        SSLServerDisconnectedException(String* message, Exception* innerException)
            :SSLException(message,innerException){}
    };
    [Serializable]
    __sealed public __gc class SSLReadException : public SSLException
    {
    public:
        SSLReadException(){}
        SSLReadException(String* message):SSLException(message){}
        SSLReadException(String* message, Exception* innerException)
            :SSLException(message,innerException){}
    };

    [Serializable]
    __sealed public __gc class SSLSendException : public SSLException
    {
    public:
        SSLSendException(){}
        SSLSendException(String* message):SSLException(message){}
        SSLSendException(String* message, Exception* innerException)
            :SSLException(message,innerException){}
        SSLSendException(String* message, UInt32 error)
            :SSLException(String::Concat(message, Convert::ToString(error))){}
    };
    } //namespace Exeptions
    namespace Misc
    {
    public __value enum ServerCertChainPolicyStatus
    {
        CERT_OK                   =S_OK,
        TRUST_NOSIGNATURE         =TRUST_E_NOSIGNATURE,
        CERT_EXPIRED              =CERT_E_EXPIRED,
        CERT_VALIDITYPERIODNESTING=CERT_E_VALIDITYPERIODNESTING,
        CERT_ROLE                 =CERT_E_ROLE,
        CERT_PATHLENCONST         =CERT_E_PATHLENCONST,
        CERT_CRITICAL             =CERT_E_CRITICAL,
        CERT_PURPOSE              =CERT_E_PURPOSE,
        CERT_ISSUERCHAINING       =CERT_E_ISSUERCHAINING,
        CERT_MALFORMED            =CERT_E_MALFORMED,
        CERT_UNTRUSTEDROOT        =CERT_E_UNTRUSTEDROOT,
        CERT_CHAINING             =CERT_E_CHAINING,
        TRUST_FAIL                =TRUST_E_FAIL,
        CERT_REVOKED              =CERT_E_REVOKED,
        CERT_UNTRUSTEDTESTROOT    =CERT_E_UNTRUSTEDTESTROOT,
        CERT_REVOCATION_FAILURE   =CERT_E_REVOCATION_FAILURE,
        CERT_CN_NO_MATCH          =CERT_E_CN_NO_MATCH,
        CERT_WRONG_USAGE          =CERT_E_WRONG_USAGE,
        TRUST_EXPLICIT_DISTRUST   =TRUST_E_EXPLICIT_DISTRUST,
        CERT_UNTRUSTEDCA          =CERT_E_UNTRUSTEDCA,
        CERT_INVALID_POLICY       =CERT_E_INVALID_POLICY,
        CERT_INVALID_NAME         =CERT_E_INVALID_NAME
    };
    public __value struct CeriticateInfo
    {
        ServerCertChainPolicyStatus PolStatus;
        long                        CertEncodingType;
        Byte                        CertData[];
    };
    public __value enum SecurityProviderProtocol
    {
        PROT_SSL3 = SP_PROT_SSL3,
        PROT_TLS1 = SP_PROT_TLS1,
        PROT_NONE = SP_PROT_NONE
    };
    public __value enum InitializeSecurityContextRequirements
    {
        ISCREQ_DELEGATE              =ISC_REQ_DELEGATE,              
        ISCREQ_MUTUAL_AUTH           =ISC_REQ_MUTUAL_AUTH,          
        ISCREQ_REPLAY_DETECT         =ISC_REQ_REPLAY_DETECT,         
        ISCREQ_SEQUENCE_DETECT       =ISC_REQ_SEQUENCE_DETECT,       
        ISCREQ_CONFIDENTIALITY       =ISC_REQ_CONFIDENTIALITY,       
        ISCREQ_USE_SESSION_KEY       =ISC_REQ_USE_SESSION_KEY,       
        ISCREQ_PROMPT_FOR_CREDS      =ISC_REQ_PROMPT_FOR_CREDS,      
        ISCREQ_USE_SUPPLIED_CREDS    =ISC_REQ_USE_SUPPLIED_CREDS,    
        ISCREQ_ALLOCATE_MEMORY       =ISC_REQ_ALLOCATE_MEMORY,       
        ISCREQ_USE_DCE_STYLE         =ISC_REQ_USE_DCE_STYLE,         
        ISCREQ_DATAGRAM              =ISC_REQ_DATAGRAM,              
        ISCREQ_CONNECTION            =ISC_REQ_CONNECTION,            
        ISCREQ_CALL_LEVEL            =ISC_REQ_CALL_LEVEL,            
        ISCREQ_FRAGMENT_SUPPLIED     =ISC_REQ_FRAGMENT_SUPPLIED,     
        ISCREQ_EXTENDED_ERROR        =ISC_REQ_EXTENDED_ERROR,        
        ISCREQ_STREAM                =ISC_REQ_STREAM,                
        ISCREQ_INTEGRITY             =ISC_REQ_INTEGRITY,             
        ISCREQ_IDENTIFY              =ISC_REQ_IDENTIFY,              
        ISCREQ_NULL_SESSION          =ISC_REQ_NULL_SESSION,          
        ISCREQ_MANUAL_CRED_VALIDATION=ISC_REQ_MANUAL_CRED_VALIDATION,
        ISCREQ_RESERVED1             =ISC_REQ_RESERVED1,             
        ISCREQ_FRAGMENT_TO_FIT       =ISC_REQ_FRAGMENT_TO_FIT
    };
    } //namespace Misc
} //namespace Common
} // namespace SSL
#pragma unmanaged
template<int nBuffs>
class CAutoSecBuffer : public SecBufferDesc
{
    SecurityFunctionTable* m_pSecurityFunc;
    SecBuffer   m_SecBuffer[nBuffs];
    bool        m_bRelease;

public:
    CAutoSecBuffer(SecurityFunctionTable* pSecurityFunc, bool bRelease)
        :m_pSecurityFunc(pSecurityFunc), m_bRelease(bRelease)
    {
        cBuffers = nBuffs;
        pBuffers = m_SecBuffer;
        ulVersion = SECBUFFER_VERSION;
    }
    ~CAutoSecBuffer()
    {
        if(m_bRelease)
        {
            for(int i=0; i<nBuffs; ++i)
            {
                m_pSecurityFunc->FreeContextBuffer(m_SecBuffer[i].pvBuffer);
                m_SecBuffer[i].pvBuffer = NULL;
            }
        }

    }
    void FreeBuffer(int nBuff)
    {
        m_pSecurityFunc->FreeContextBuffer(m_SecBuffer[nBuff].pvBuffer);
        m_SecBuffer[nBuff].pvBuffer = NULL;
    }
    void SetSecurityBufferToken(int nBuff, void* pvBuffer, int nLen)
    {
        m_SecBuffer[nBuff].BufferType = SECBUFFER_TOKEN;
        m_SecBuffer[nBuff].cbBuffer = nLen;
        m_SecBuffer[nBuff].pvBuffer = pvBuffer;
    }
    void SetSecurityBufferData(int nBuff, void* pvBuffer, int nLen)
    {
        m_SecBuffer[nBuff].BufferType = SECBUFFER_DATA;
        m_SecBuffer[nBuff].cbBuffer = nLen;
        m_SecBuffer[nBuff].pvBuffer = pvBuffer;
    }
    void SetSecurityBufferStreamHeader(int nBuff, void* pvBuffer, int nLen)
    {
        m_SecBuffer[nBuff].BufferType = SECBUFFER_STREAM_HEADER;
        m_SecBuffer[nBuff].cbBuffer = nLen;
        m_SecBuffer[nBuff].pvBuffer = pvBuffer;
    }
    void SetSecurityBufferStreamTrailer(int nBuff, void* pvBuffer, int nLen)
    {
        m_SecBuffer[nBuff].BufferType = SECBUFFER_STREAM_TRAILER;
        m_SecBuffer[nBuff].cbBuffer = nLen;
        m_SecBuffer[nBuff].pvBuffer = pvBuffer;
    }
    void SetSecurityBufferEmpty(int nBuff)
    {
        m_SecBuffer[nBuff].BufferType = SECBUFFER_EMPTY;
        m_SecBuffer[nBuff].cbBuffer   = 0;
        m_SecBuffer[nBuff].pvBuffer   = NULL;
    }
    SecBuffer& operator[](unsigned int i)
    {
        return m_SecBuffer[i];
    }
private:
};

struct WStringComp
{   // define hash function for strings
    enum { // parameters for hash table
    bucket_size = 4, // 0 < bucket_size
    min_buckets = 8}; // min_buckets = 2 ^^ N, 0 < N
    size_t operator()(const std::wstring& s1) const
    { 
        const wchar_t *p = s1.c_str();
        size_t nHash = 0;
        while (*p != '\0')
            nHash = (nHash<<5) + nHash + (*p++);
        return nHash;
    }
    bool operator()(const std::wstring &s1, const std::wstring &s2) const
    { // test if s1 ordered before s2
        return (s1 < s2);
    }
};
#pragma managed
bool LoadSecurityLibrary(HMODULE, SecurityFunctionTable __nogc*&);
bool VerifyCertificate(bool fTargetServer, SecurityFunctionTable __nogc*, CtxtHandle __nogc*, LPWSTR pwszServerName, DWORD dwCertFlags, SSL::Common::Misc::CeriticateInfo* CertInfo);
