#include <stdio.h>

#include "base64.h"


unsigned int get_base64_len(unsigned int b64_len)
{
  return(((b64_len + 3)/4) * 3);

}/*get_base64_len*/

/*http://josefsson.org/base-encoding*/
unsigned int base64_decode(unsigned char *base64, 
								unsigned int  b64_len, 
								unsigned char *buffer, 
								unsigned int  *buffer_len)
{
  unsigned int  offset    = 0;
	unsigned int  idx       = 0;
  unsigned int  tmp       = 0;


  if((NULL == buffer) ||
	 	 (NULL == buffer_len))
	{
    return 1;					
	}
  
	idx = get_base64_len(b64_len);

	/*resetting idx to 0, so that It can be re-used*/
	idx = 0;
  for(; offset < b64_len; offset +=4)
	{
    tmp = (((((b64[base64[offset + 0]] <<  6  |
					     b64[base64[offset + 1]]) << 6) |
					     b64[base64[offset + 2]]) << 6) |
					     b64[base64[offset + 3]]);

		if(b64[base64[offset + 2]] == 0x40)
		{	
	    /*There are two padd characters '=='*/
		  buffer[idx++] = (tmp & 0xFF0000U) >> 16;
		}
		else if(b64[base64[offset + 3]] == 0x40)
		{
			/*There is only one pad character '='*/			
		  buffer[idx++] = (tmp & 0xFF0000U) >> 16;
		  buffer[idx++] = (tmp & 0x00FF00U) >> 8 ;
		}
		else
		{
		  /*There are no pad character*/				
		  buffer[idx++] = (tmp & 0xFF0000U) >> 16;
		  buffer[idx++] = (tmp & 0x00FF00U) >> 8 ;
		  buffer[idx++] = (tmp & 0x0000FFU) >> 0 ;
		}
	}
  *buffer_len = idx;	
  return 0;

}/*base64_decode*/

unsigned int base64_encode(unsigned char *byte_stream, 
								unsigned int  len, 
								unsigned char *base64_buffer, 
								unsigned int  *base64_buffer_len)
{
  unsigned int  offset    = 0;
	unsigned int  idx       = 0;
  unsigned int  tmp       = 0;

  unsigned char base64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";

  if((NULL == base64_buffer) ||
	 	 (NULL == base64_buffer_len))
	{
    return 1;					
	}

  for(; offset < len; offset +=3)
	{
		if(len - offset >= 3)
		{
      tmp = ((byte_stream[offset] << 8 |
			  		 byte_stream[offset + 1]) << 8 |
				  	 byte_stream[offset + 2]) & 0xFFFFFF;

		  base64_buffer[idx++] = base64[(tmp >> 18)  & 0x3F];
		  base64_buffer[idx++] = base64[(tmp >> 12)  & 0x3F];
		  base64_buffer[idx++] = base64[(tmp >> 6 )  & 0x3F];
		  base64_buffer[idx++] = base64[(tmp >> 0 )  & 0x3F];
		}
		else if((len - offset) == 1)
		{
      tmp = byte_stream[offset];

		  base64_buffer[idx++] = base64[(tmp >> 2)  & 0x3F];
		  base64_buffer[idx++] = base64[(tmp << 4)  & 0x3F];
      base64_buffer[idx++] = '=';
      base64_buffer[idx++] = '=';
      			
		}
	  else if((len - offset) == 2)
		{
      tmp = (byte_stream[offset] << 8 |
			  		 byte_stream[offset + 1]) & 0xFFFF; 

		  base64_buffer[idx++] = base64[(tmp >> 10)  & 0x3F];
		  base64_buffer[idx++] = base64[(tmp >> 3)   & 0x3F];
		  base64_buffer[idx++] = base64[(tmp << 3 )  & 0x3F];
			base64_buffer[idx++] = '=';
		}	
	}
  *base64_buffer_len = idx;	
  return idx;

}/*base64_encode*/

