/**************************************************************************
   THIS CODE AND INFORMATION IS PROVIDED 'AS IS' WITHOUT WARRANTY OF
   ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO
   THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
   PARTICULAR PURPOSE.
   Author: Leon Finker  7/2002
**************************************************************************/
#include "stdafx.h"
#include "sslcommon.h"


bool LoadSecurityLibrary(HMODULE hSecurity, SecurityFunctionTable __nogc*& pSecurityFunc)
{
	if(hSecurity != NULL)
		return true;
	INIT_SECURITY_INTERFACE pInitSecurityInterface;
	OSVERSIONINFO VerInfo;
	char lpszDLL[MAX_PATH];

	//
	//  Find out which security DLL to use, depending on
	//  whether we are on Win2k, NT or Win9x
	//

	VerInfo.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);
	if (!GetVersionEx (&VerInfo))   
	{
		return false;
	}

	if (VerInfo.dwPlatformId == VER_PLATFORM_WIN32_NT 
		&& VerInfo.dwMajorVersion == 4)
	{
		strcpy (lpszDLL, "Security.dll" );
	}
	else if (VerInfo.dwPlatformId == VER_PLATFORM_WIN32_WINDOWS ||
		VerInfo.dwPlatformId == VER_PLATFORM_WIN32_NT )
	{
		strcpy (lpszDLL, "Secur32.dll" );
	}
	else
	{
		return false;
	}

	//
	//  Load Security DLL
	//

	hSecurity = LoadLibrary(lpszDLL);
	if(hSecurity == NULL)
	{
		return false;
	}

	pInitSecurityInterface = (INIT_SECURITY_INTERFACE)GetProcAddress(
									hSecurity,
									"InitSecurityInterfaceA");
	
	if(pInitSecurityInterface == NULL)
	{
		FreeLibrary(hSecurity);
		hSecurity = NULL;
		return false;
	}

	pSecurityFunc = pInitSecurityInterface();

	if(pSecurityFunc == NULL)
	{
		FreeLibrary(hSecurity);
		hSecurity = NULL;
		return false;
	}
	return true;
}

bool VerifyCertificate(bool fTargetServer, SecurityFunctionTable __nogc* pSecurityFunc, CtxtHandle __nogc* phContext, LPWSTR pwszServerName, DWORD dwCertFlags, SSL::Common::Misc::CeriticateInfo* CertInfo)
{
	HTTPSPolicyCallbackData  polHttps;
	CERT_CHAIN_POLICY_PARA   PolicyPara;
	CERT_CHAIN_POLICY_STATUS PolicyStatus;
	CERT_CHAIN_PARA          ChainPara;
	PCCERT_CHAIN_CONTEXT     pChainContext = NULL;
	PCCERT_CONTEXT			 pServerCert = NULL;

	SECURITY_STATUS Status = pSecurityFunc->QueryContextAttributesA(phContext,
									SECPKG_ATTR_REMOTE_CERT_CONTEXT,
									(PVOID)&pServerCert);
	if(Status != SEC_E_OK || pServerCert == NULL)
	{
		return false;
	}
	//
	// Build certificate chain.
	//
	ZeroMemory(&ChainPara, sizeof(ChainPara));
	ChainPara.cbSize = sizeof(ChainPara);
	ChainPara.RequestedUsage.dwType = USAGE_MATCH_TYPE_OR;
	
	LPSTR ServerUsages[] = {  szOID_PKIX_KP_SERVER_AUTH,
							szOID_SERVER_GATED_CRYPTO,
							szOID_SGC_NETSCAPE };
	LPSTR ClientUsage = szOID_PKIX_KP_CLIENT_AUTH;

	ChainPara.RequestedUsage.Usage.cUsageIdentifier     = fTargetServer?3:1;
	ChainPara.RequestedUsage.Usage.rgpszUsageIdentifier = fTargetServer?ServerUsages:&ClientUsage;

	if(!CertGetCertificateChain(NULL,pServerCert,NULL,
								pServerCert->hCertStore,&ChainPara,
								0,NULL,&pChainContext))
	{
		if(pChainContext)
		{
			CertFreeCertificateChain(pChainContext);
		}
	}
	//
	// Validate certificate chain.
	// 
	ZeroMemory(&polHttps, sizeof(HTTPSPolicyCallbackData));
	polHttps.cbStruct           = sizeof(HTTPSPolicyCallbackData);
	polHttps.dwAuthType         = fTargetServer?AUTHTYPE_SERVER:AUTHTYPE_CLIENT;
	polHttps.fdwChecks          = dwCertFlags;
	polHttps.pwszServerName     = pwszServerName;

	memset(&PolicyPara, 0, sizeof(PolicyPara));
	PolicyPara.cbSize            = sizeof(PolicyPara);
	PolicyPara.pvExtraPolicyPara = &polHttps;

	memset(&PolicyStatus, 0, sizeof(PolicyStatus));
	PolicyStatus.cbSize = sizeof(PolicyStatus);

	if(!CertVerifyCertificateChainPolicy(
							CERT_CHAIN_POLICY_SSL,
							pChainContext,
							&PolicyPara,
							&PolicyStatus))
	{
		if(pChainContext)
		{
			CertFreeCertificateChain(pChainContext);
			pChainContext = NULL;
		}
	}
	bool	bRet	=	true;
	if(CertInfo != NULL && pChainContext != NULL)
	{
		Byte CertData[] = new Byte[pServerCert->cbCertEncoded];
		Marshal::Copy(IntPtr(pServerCert->pbCertEncoded), CertData, 0, pServerCert->cbCertEncoded);
		CertInfo->PolStatus = SSL::Common::Misc::ServerCertChainPolicyStatus(PolicyStatus.dwError);
		CertInfo->CertEncodingType = pServerCert->dwCertEncodingType;
		CertInfo->CertData = CertData;
		bRet	=	false;
	}
	if(pChainContext)
	{
		CertFreeCertificateChain(pChainContext);
	}
	return bRet;
}