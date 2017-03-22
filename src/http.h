#ifndef __HTTP_H__
#define __HTTP_H__

#include <stdio.h>
#include <libxml/parser.h>
#include <libxml/tree.h>
#include <assert.h>

int http_response_success(const char * response, int response_length, unsigned char *out_ptr);

int http_response_process(const char *response, int response_length, unsigned char *out_ptr);


int http_process_xml_response(const unsigned char *xml_response, unsigned int xml_response_len, unsigned char *out_ptr);

#endif /*__HTTP_H__*/
