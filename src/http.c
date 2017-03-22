#ifndef __HTTP_C__
#define __HTTP_C__

#include "http.h"

int http_build_ui_auth_response(xmlNode *root_elem, unsigned char *out_ptr)
{
  xmlNode *curr_node = NULL;
  unsigned char tmp_buff[2048];
  int rc = -1;

  for(curr_node = root_elem; curr_node;	curr_node = curr_node->next)
	{
    if(curr_node->type == XML_ELEMENT_NODE)
		{
      if(!strncmp(curr_node->name, "AuthRes", 7))
			{
        memset((void *)tmp_buff, 0, sizeof(tmp_buff));
				if(!strncmp(xmlGetProp(curr_node, "ret"), "y", 1))
				{
	        rc = snprintf((char *)tmp_buff, sizeof(tmp_buff),
			         "%s%s%s%s%s"
						   "%s%s%s",
			         "ret=",
						   xmlGetProp(curr_node, "ret"),
						   "&code=",
						   xmlGetProp(curr_node, "code"),
						   "&ts=",
						   xmlGetProp(curr_node, "ts"),
						   "&txn=",
						   xmlGetProp(curr_node, "txn"));
				  memcpy((void *)out_ptr, tmp_buff, rc);
				}
				else
				{
					/*Failure Response*/
					rc = snprintf((char *)tmp_buff, sizeof(tmp_buff),
			         "%s%s%s%s%s"
						   "%s%s%s",
			         "ret=",
						   xmlGetProp(curr_node, "ret"),
						   "&err=",
						   xmlGetProp(curr_node, "err"),
						   "&ts=",
						   xmlGetProp(curr_node, "ts"),
						   "&txn=",
						   xmlGetProp(curr_node, "txn"));
				  memcpy((void *)out_ptr, tmp_buff, rc);
				}
				return(rc);
			}			
		}/*if()*/			
	}/*for(;;)*/
	return(0);

}/*http_build_ui_auth_response*/

void print_element_names(xmlNode *a_node)
{
    xmlNode *cur_node = NULL;

    for (cur_node = a_node; cur_node; cur_node = cur_node->next) 
		{
      if(cur_node->type == XML_ELEMENT_NODE) 
			{
        printf("node type: Element, name: %s\n", cur_node->name);
				if(!strncmp(cur_node->name, "AuthRes", 7))
				{
			    fprintf(stderr, "code => %s\n", xmlGetProp(cur_node, "code"));
			    fprintf(stderr, "ret => %s\n", xmlGetProp(cur_node, "ret"));
			    fprintf(stderr, "info => %s\n", xmlGetProp(cur_node, "info"));
			    fprintf(stderr, "ts => %s\n", xmlGetProp(cur_node, "ts"));
			    fprintf(stderr, "txn => %s\n", xmlGetProp(cur_node, "txn"));

				}
      }
      print_element_names(cur_node->children);
   }
}/*print_element_names*/

int http_process_xml_response(const unsigned char *xml_response, unsigned int xml_response_len, unsigned char *out_ptr)
{
	unsigned char *xml_doc_ptr = NULL;
  xmlNode *root_elem = NULL;

  xml_doc_ptr = xmlParseMemory(xml_response, xml_response_len);
	
	if((xml_doc_ptr == NULL) || 
	   (xmlDocGetRootElement(xml_doc_ptr) == NULL)) 
	{
    fprintf(stderr, "Error: Unable to parse auth_xml\n");
		if(NULL == xml_doc_ptr)
		{
      xmlFreeDoc(xml_doc_ptr);			
		}
		return(-9);		
	}
  root_elem = xmlDocGetRootElement(xml_doc_ptr);
  print_element_names(root_elem);

	return(http_build_ui_auth_response(root_elem, out_ptr));

}/*http_process_xml_response*/

int http_response_success(const char * response, int response_length, unsigned char *out_ptr)
{
  char *tmp_response = NULL;
	int rc = -1;
  char *line_str = NULL;
	char mime_tag[128];
	char mime_value[1024];
  char is_payload_chunked = 0;
  char is_payload_start   = 0;
  unsigned char *xml_response = NULL;
  unsigned int  xml_response_len = 0;
  unsigned int  offset = 0;

	tmp_response = (char *)malloc(response_length);
	memset((void *)tmp_response, 0, response_length);

  memcpy((void *)tmp_response, response, response_length);
  
  line_str = strtok(tmp_response, "\n");
  offset   = strlen((const char *)line_str) + 1/*for \r*/;
  
	while(NULL != (line_str = strtok(NULL, "\n")))
	{
		offset += strlen((const char *)line_str) + 1/*for \r*/;

    if(!is_payload_start)
    {
		  memset((void *)mime_tag, 0, sizeof(mime_tag));
      rc = sscanf((const char *)line_str, "%[^:]:%*s",mime_tag);
      assert(rc == 1);
      /*scan for Transfer-Encoding*/
      if(!strncmp((const char *)mime_tag, "Transfer-Encoding", 17))
	    {
			  memset((void *)mime_value, 0, sizeof(mime_value));
        rc = sscanf((const char *)line_str, "%*[^:]:%s",mime_value);
			  if(!strncmp((const char *)mime_value, "chunked", 7))
        {
          /*Payload is chenked*/	
	        is_payload_chunked = 1;
			  }
		  }
      else if(!strncmp((const char *)mime_tag, "\r", 1))
	    {
        /*got the empty line*/
     	  is_payload_start = 1;		
	    }
		}
		else if(1 == is_payload_start && 1 == is_payload_chunked)
		{
      memset((void *)mime_value, 0, sizeof(mime_value));
      rc = snprintf(mime_value, sizeof(mime_value), "0x%s",line_str);
			rc = sscanf((const char *)mime_value, "0x%x", &xml_response_len);

			xml_response = (unsigned char *)malloc(xml_response_len);
			assert(xml_response != NULL);
			
			memcpy((void *)xml_response, (const void *)&response[offset], xml_response_len); 
			rc = http_process_xml_response(xml_response, xml_response_len, out_ptr);
			free(xml_response);
			return(rc);
	  
		}
	}
  free(tmp_response);
}/*http_response_success*/


int http_response_process(const char *response, int response_length, unsigned char *out_ptr)
{
  int rc = -1;
  int status = -1;
	char status_str[8];

  char status_code[32];
  char protocol[8];
	char host[64];
  char *line_ptr = NULL;
	char mime_tag[512];
	char mime_value[2048];
	char *tmp_response = NULL;

  int fd = -1;
  
	memset((void *)status_code, 0, sizeof(status_code));
	memset((void *)protocol, 0, sizeof(protocol));
	memset((void *)host, 0, sizeof(host));

	tmp_response = (char *)malloc(response_length);
	memset((void *)tmp_response, 0, response_length);
  fprintf(stderr, "response length is %d\n", response_length);
	memcpy((void *)tmp_response, response, response_length);

  line_ptr = strtok(tmp_response, "\r\n");
  fprintf(stderr, "line_ptr is %s\n", line_ptr);
	rc = sscanf(line_ptr, "HTTP/1.1 %s %s", status_str, status_code);
	status = atoi(status_str);

	if(302 == status)
	{
    /*Retrieve the Location Value*/
    while(NULL != (line_ptr = strtok(NULL, "\r\n")))
		{
			memset((void *)mime_tag, 0, sizeof(mime_tag));
			memset((void *)mime_value, 0, sizeof(mime_value));

      rc = sscanf(line_ptr, "%[^:]:%s",	mime_tag, mime_value);
	    if(rc == 2)
			{
        if(!strncmp(mime_tag, "Location", 8))
				{
				  rc = sscanf(mime_value, "%[^:]://%[^/]%*s", protocol, host);	
					fprintf(stderr, "Protocol %s host %s\n", protocol, host);
					return(1);
				}
			}
		}/*End of while*/
	}
	else if(200 == status)
	{
		fprintf(stderr, "Response is SUCCESS\n");
    /*Received the Success Response*/
    return(http_response_success((const char *)response, response_length, out_ptr));
	}
	return(0);
}/*otp_response_process*/


#endif /*__HTTP_C__*/
