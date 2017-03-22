#ifndef __DSIG_H__
#define __DSIG_H__

#ifdef XML_SECURITY
#include <libxml/tree.h>
#include <libxml/xmlmemory.h>
#include <libxml/parser.h>

#ifndef XMLSEC_NO_XSLT
#include <libxslt/xslt.h>
#endif

#include <xmlsec/xmlsec.h>
#include <xmlsec/xmltree.h>
#include <xmlsec/xmldsig.h>
#include <xmlsec/templates.h>
#include <xmlsec/crypto.h>
#endif

int dsig_main(const unsigned char *in_xml, unsigned char *signed_xml);

int dsig_cleanup(void);

int dsig_sign_auth_xml(const unsigned char *auth_xml_ptr, unsigned char *signed_xml_ptr);

int dsig_init(void);


#endif /*__DSIG_H__*/
