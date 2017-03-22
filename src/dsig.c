#ifndef __DSIG_C__
#define __DSIG_C__

#include "uidai.h"
#include "dsig.h"

extern uidai_context_t uidai_ctx;

int dsig_init(void)
{
	xmlInitParser();
	LIBXML_TEST_VERSION
	xmlLoadExtDtdDefaultValue = XML_DETECT_IDS | XML_COMPLETE_ATTRS;
	xmlSubstituteEntitiesDefault(1);
#ifndef XMLSEC_NO_XSLT
	xmlIndentTreeOutput = 1; 
#endif
        	
  /*Init xmlsec library */
	if(xmlSecInit() < 0) 
	{
		fprintf(stderr, "Error: xmlsec initialization failed.\n");
		return -1;
	}

  /*Check loaded library version */
	if (xmlSecCheckVersion() != 1) 
	{
		fprintf(stderr, "Error: loaded xmlsec library version is not compatible.\n");
		return -2;
	}

	if(xmlSecCryptoDLLoadLibrary(NULL) < 0) 
	{
		fprintf(stderr, "Loding of Dynamic library failed\n");
		return -3;	
	}

  /*Init crypto library */
	if(xmlSecCryptoAppInit(NULL) < 0) 
	{
		fprintf(stderr, "Error: crypto initialization failed.\n");
		return -4;
	}

  /*Init xmlsec-crypto library */
	if(xmlSecCryptoInit() < 0) 
	{
		fprintf(stderr, "Error: xmlsec-crypto initialization failed.\n");
		return -5;
	}
  return(0);

}/*dsig_init*/

int dsig_sign_auth_xml(const unsigned char *auth_xml_ptr, unsigned char *signed_xml_ptr)
{
  xmlChar    *xmlBuff      = NULL;
	xmlDocPtr  auth_xml      = NULL;
	xmlNodePtr signNode      = NULL,
						 refNode       = NULL,
						 keyInfoNode   = NULL;
	xmlSecDSigCtxPtr dsigCtx = NULL;
	int        res = -1;
	X509     *x;
	EVP_PKEY *pkey;
	PKCS12   *p12;
	STACK_OF(X509) *ca = NULL;
	FILE *fp;
	unsigned char *public_certificate = "public_cer.pem";
	unsigned char *private_certificate = "private_cer";

	x = X509_new();

	fp = fopen(uidai_ctx.private_certificate_file, "rb");

	p12 = d2i_PKCS12_fp(fp, NULL);
	fclose(fp);

	if(!PKCS12_parse(p12, uidai_ctx.password, &pkey, &x, &ca)) 
	{
		printf(" Error while parsing\n");
	}
	PKCS12_free(p12);
	
  //X509 Certificate
	fp = fopen(public_certificate,"w");
	PEM_write_X509(fp, x);
	fclose(fp);

  //RSA Private Certificate
	fp = fopen(private_certificate,"w");
	PEM_write_PrivateKey(fp, pkey, NULL, NULL, 0, NULL, NULL);
	fclose(fp);

  auth_xml = xmlParseMemory(auth_xml_ptr, strlen(auth_xml_ptr));
	if((auth_xml == NULL) || 
	   (xmlDocGetRootElement(auth_xml) == NULL)) 
	{
    fprintf(stderr, "Error: Unable to parse auth_xml\n");
		if(NULL == auth_xml)
		{
      xmlFreeDoc(auth_xml);			
		}
		return(-9);		
	}
  /*create signature template for RSA-SHA1 enveloped signature */
	signNode = xmlSecTmplSignatureCreate(auth_xml, 
			                                 xmlSecTransformInclC14NId,
			                                 xmlSecTransformRsaSha1Id, 
																			 NULL);
	if(signNode == NULL) 
	{
		fprintf(stderr, "Error: failed to create signature template\n");
		if(auth_xml != NULL)
			xmlFreeDoc(auth_xml); 
		return(-1);
	}

  /*add <dsig:Signature/> node to the doc */
	xmlAddChild(xmlDocGetRootElement(auth_xml), signNode);
	refNode = xmlSecTmplSignatureAddReference(signNode,
			                                      xmlSecTransformSha1Id,
																					 	NULL,
																					 	"", 
																						NULL);
	if(refNode == NULL) 
	{
		fprintf(stderr, "Error: failed to add reference to signature template\n");
		if (auth_xml != NULL)
			xmlFreeDoc(auth_xml); 
		return(-2);
	}

  /*add enveloped transform */
	if(xmlSecTmplReferenceAddTransform(refNode,
		                                 xmlSecTransformEnvelopedId) == NULL) 
	{
		fprintf(stderr, "Error: failed to add enveloped transform to reference\n");
		if (auth_xml != NULL)
			xmlFreeDoc(auth_xml); 
		return(-3);
	}
    
  /*add <dsig:KeyInfo/> and <dsig:X509Data/> */
	keyInfoNode = xmlSecTmplSignatureEnsureKeyInfo(signNode, NULL);
	if(keyInfoNode == NULL) 
	{
		fprintf(stderr, "Error: failed to add key info\n");
		if (auth_xml != NULL)
			xmlFreeDoc(auth_xml); 
		return(-4);
	}
	xmlNodePtr x509Node=xmlSecTmplKeyInfoAddX509Data(keyInfoNode);

	xmlSecTmplX509DataAddSubjectName(x509Node);
	xmlSecTmplX509DataAddCertificate(x509Node);

  /*create signature context, we don't need keys manager in this example */
	dsigCtx = xmlSecDSigCtxCreate(NULL);
	if(dsigCtx == NULL) 
	{
		fprintf(stderr,"Error: failed to create signature context\n");
		if (auth_xml != NULL)
			xmlFreeDoc(auth_xml); 
		return(-5);
	}
	
  /*load private key, assuming that there is not password */
	dsigCtx->signKey = xmlSecCryptoAppKeyLoad(private_certificate,
		                                        xmlSecKeyDataFormatPem, 
																						uidai_ctx.password, 
																						NULL, 
																						NULL);
	if(dsigCtx->signKey == NULL) 
	{
		fprintf(stderr,"Error: failed to load private pem key from \"%s\"\n", private_certificate);
		if (auth_xml != NULL)
			xmlFreeDoc(auth_xml); 
		if (dsigCtx != NULL)
			xmlSecDSigCtxDestroy(dsigCtx);
		return(-6);
	}
    
  /*load certificate and add to the key */
	if(xmlSecCryptoAppKeyCertLoad(dsigCtx->signKey, 
				                        public_certificate,
		                            xmlSecKeyDataFormatPem) < 0) 
	{
		fprintf(stderr,"Error: failed to load pem certificate \"%s\"\n", public_certificate);
		if(auth_xml != NULL)
			xmlFreeDoc(auth_xml); 
		if (dsigCtx != NULL)
			xmlSecDSigCtxDestroy(dsigCtx);
		return(-7);
	}
  /*sign the template */
	if(xmlSecDSigCtxSign(dsigCtx, signNode) < 0)
 	{
		fprintf(stderr,"Error: signature failed\n");
		if (auth_xml != NULL)
			xmlFreeDoc(auth_xml); 
		if (dsigCtx != NULL)
			xmlSecDSigCtxDestroy(dsigCtx);
		return(-8);
	}
	unlink(public_certificate);
	unlink(private_certificate);
	
	int bufferSize=0;
	xmlDocDumpFormatMemory(auth_xml, &xmlBuff, &bufferSize, 1);

	if (dsigCtx != NULL)
		xmlSecDSigCtxDestroy(dsigCtx);
	if (auth_xml != NULL)
		xmlFreeDoc(auth_xml); 
	
	memcpy((void *)signed_xml_ptr, xmlBuff, bufferSize);
	return(bufferSize);

}/*dsig_sign_auth_xml*/

int dsig_cleanup(void)
{
	xmlSecCryptoShutdown();
	xmlSecCryptoAppShutdown();
	xmlSecShutdown();

	xsltCleanupGlobals();            
	xmlCleanupParser();
}/*dsig_cleanup*/

int dsig_main(const unsigned char *in_xml, unsigned char *signed_xml)
{
  dsig_init();
  dsig_sign_auth_xml(in_xml, signed_xml);	
	dsig_cleanup();

}/*dsig_main*/


#endif /*__DSIG_C__*/
