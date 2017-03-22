#ifndef __AUTH_C__
#define __AUTH_C__


#include "common.h"
#include "tcpc.h"
#include "uidai.h"
#include "dsig.h"
#include "http.h"
#include "auth.h"

#define ASA_KEY "MH4hSkrev2h_Feu0lBRC8NI-iqzT299_qPSSstOFbNFTwWrie29ThDo"
#define AUA_KEY "MBFWjkJHNF-fLidl8oOHtUwgL5p1ZjDbWrqsMEVEJLVEDpnlNj_CZTg"

int main(int argc, char *argv[])
{
  char ip[16]; 
  int fd  = -1;
  int rc  = -1;
	int len = -1;

  unsigned char *signed_xml = NULL;
  char *http_req = NULL;

	char resp_buffer[5048];
  char http_header[1024];
  char auth_xml[2000];
  int offset = 0;
	unsigned char parsed_auth_res[2048];

  fd = tcp_socket();

  rc = tcp_get_ip_address(argv[1], (char *)ip);
  assert(rc == 0);

  if(tcp_connect(fd, ip, atoi(argv[2])))
	{
    perror("\nConnect Failed:");
		return(-1);
	}
	memset((void *)auth_xml, 0, sizeof(auth_xml));

  uidai_main((const unsigned char *)"../keys/uidai_auth_stage.cer", 
			(const unsigned char *)"../keys/Staging_Signature_PrivateKey.p12", 
			(unsigned char *)auth_xml);

  fprintf(stderr, "Auth XML\n %s\n", auth_xml);
	signed_xml = (char *)malloc(5000);

  /*Digitally Sign the XML*/
  dsig_main(auth_xml, signed_xml); 
	
	if(NULL == signed_xml)
	{
    fprintf(stderr, "Signing of xml failed\n");
    return NULL;		
	}

  len = strlen((const char *)signed_xml);
	fprintf(stderr, "signed xml length is %d\n", len);
	fprintf(stderr, "Signed XML is \n%s", signed_xml);
	/*Http Header*/
	memset((void *)http_header, 0,sizeof(http_header));
  /*https://<host>/otp/<ver>/<ac>/<uid[0]>/<uid[1]>/<asalk>*/

  rc = snprintf(http_header, sizeof(http_header),
			"%s%s%s%s%s"
			"%s%s%d%s%s",
		  "POST http://auth.uidai.gov.in/1.6/public/9/9/",
		  ASA_KEY,
      " HTTP/1.1\r\n",
			"Host: auth.uidai.gov.in \r\n",
			"Content-Type: text/xml\r\n",
			"Connection: Keep-alive\r\n",
			"Content-Length: ",
			len,
			"\r\n",
			"\n\n");

	fprintf(stderr, "rc %d\thttp_header is \n%s\n", rc, http_header);
	http_req = (char *)malloc(rc + len);
  memset((void *)http_req, 0, (rc + len));

  memcpy((void *)http_req, http_header, rc);
  memcpy((void *)&http_req[rc -1], signed_xml, len);

	rc = tcp_write(fd, (char *)http_req, (rc + len -1), 0);

	fprintf(stderr, "sent request length %d signed xml length %d\n", rc, len);
  free(http_req);
	len = rc;

	free(signed_xml);
	memset((void *)resp_buffer, 0, sizeof(resp_buffer));
  rc = 0;

  do
	{
	  rc = tcp_read(fd, (char *)&resp_buffer[offset], sizeof(resp_buffer), 0);
    offset += rc;
    fprintf(stderr, "\nreceived response length is %d\n", rc);
	
	}while(rc != 0);
	fprintf(stderr, "\nThe Response is \n%s\n", resp_buffer);

  fprintf(stderr, "Total Bytes are Received is %d\n", offset);

	memset((void *)parsed_auth_res, 0, sizeof(parsed_auth_res));
	/*Process the response*/
	rc = http_response_process((const char *)resp_buffer, offset, (unsigned char *)parsed_auth_res);
	fprintf(stderr, "parsed length is %d and out is %s\n", rc, parsed_auth_res);

}/*main*/


#endif /*__AUTH_C__*/
