#ifndef __UIDAI_C__
#define __UIDAI_C__

#include "uidai.h"
#include "base64.h"

#define AUA_KEY "MBFWjkJHNF-fLidl8oOHtUwgL5p1ZjDbWrqsMEVEJLVEDpnlNj_CZTg"

/*uidai context Initialization*/
uidai_context_t uidai_ctx = 
{
  .skey       = "",
  .skey_b64   = "",
  .pid_b64    = "",
  .hmac_b64   = "",
  .demo.bio_demographic_count = 0,
	.pid_xml    = "",
	.pid_ver    = "1.0",
	.auth_xml   = "",
  .certificate_expiry = "20200916",
  .password   = "public",

  .auth_attr  = {.uid = {.is_present = 1, .value = ""},   
		             .tid = {.is_present = 1, .value = "public"}, 
								 .ac  = {.is_present = 1, .value = "public"}, 
								 .sa  = {.is_present = 1, .value = "public"},
						 		 .ver = {.is_present = 1, .value = "1.6"}, 
								 .txn = {.is_present = 1, .value = "SampleUidaiClient"}, 
								 .lk  = {.is_present = 1, .value = ""} },

  .uses_attr  = {.pi  = {.is_present = 1, .value = "y"},  
		             .pfa = {.is_present = 1, .value = "n"},
					 			 .pa  = {.is_present = 1, .value = "n"},
					 			 .bio = {.is_present = 1, .value = "n"}, 
				 				 .bt  = {.is_present = 1, .value = "n"},
								 .pin = {.is_present = 1, .value = "n"}, 
 								 .otp = {.is_present = 1, .value = "n"} },	

  .meta_attr  = {.udc = {.is_present = 1, .value = "NC"},
	 	             .fdc = {.is_present = 1, .value = "NA"},
								 .idc = {.is_present = 1, .value = "NA"}, 
						 		 .pip = {.is_present = 1, .value = "127.0.0.1"}, 
								 .lot = {.is_present = 1, .value = "P"}, 
							 	 .lov = {.is_present = 1, .value = "500008"} },
   /*Demographic Details*/
  .demo       = {.is_pi_present = 1, .pi_demographic = {.ms     = {.is_present = 1, .value = "E"},
		                                                    .mv     = {.is_present = 1, .value = "100"},
		                                                    .name   = {.is_present = 1, .value = "Shivshankar Choudhury"},
		                                                    .lname  = {.is_present = 0, .value = ""},
		                                                    .lmv    = {.is_present = 0, .value = ""},
		                                                    .gender = {.is_present = 0, .value = ""},
		                                                    .dob    = {.is_present = 0, .value = ""},
		                                                    .dobt   = {.is_present = 0, .value = ""},
		                                                    .age    = {.is_present = 0, .value = ""},
		                                                    .phone  = {.is_present = 0, .value = ""},
		                                                    .email  = {.is_present = 0, .value = ""} },
	               /*proof of Address*/
	               .is_pfa_present = 0, .pfa_demographic = {.ms  = {.is_present = 0, .value = ""},
									                                        .mv  = {.is_present = 0, .value = ""},
									                                        .av  = {.is_present = 0, .value = ""},
									                                        .lav = {.is_present = 0, .value = ""},
									                                        .lmv = {.is_present = 0, .value = ""} },
								 /*Proof Of Address*/
	               .is_pa_present  = 0, .pa_demographic  = {.ms      = {.is_present = 0, .value = ""},
									                                        .co      = {.is_present = 0, .value = ""},
									                                        .house   = {.is_present = 0, .value = ""},
									                                        .street  = {.is_present = 0, .value = ""},
									                                        .lm      = {.is_present = 0, .value = ""},
									                                        .loc     = {.is_present = 0, .value = ""},
									                                        .vtc     = {.is_present = 0, .value = ""},
									                                        .subdist = {.is_present = 0, .value = ""},
									                                        .state   = {.is_present = 0, .value = ""},
									                                        .po      = {.is_present = 0, .value = ""} },
								 /*Proof of Bio demographics - thump Impression*/
#if 0
	               .is_bio_present = 0, .bio_demographic[1] = {{.type = {.is_present = 0, .value = ""},
									                                            .posh = {.is_present = 0, .value = ""}}},
#endif
								 .is_bio_present = 0,
								 /*OTP*/
	               .is_pv_present  = 0, .pv_demographic  = {.otp = {.is_present = 0, .value = ""},
									                                        .pin = {.is_present = 0, .value = ""} }
	              }
};

int uidai_sha256(char *pid_xml_ptr, unsigned char *sha256_ptr)
{    
  SHA256_CTX ctx;

  SHA256_Init(&ctx);
  SHA256_Update(&ctx, pid_xml_ptr, strlen((const char *)pid_xml_ptr));
  SHA256_Final(sha256_ptr, &ctx);
  return 0;
}

int uidai_aes256_encryption(unsigned char *pid_data, int pid_len, unsigned char *encrypted_pid_ptr)
{
  int tmp_len;
  unsigned char iv[32];
	int  encrypted_pid_len = 0;

  EVP_CIPHER_CTX *x;

  x = EVP_CIPHER_CTX_new();

  EVP_CIPHER_CTX_reset(x);
  
  EVP_CIPHER_CTX_set_padding(x, 1);

  if (!EVP_EncryptInit_ex(x, EVP_aes_256_ecb(), NULL, uidai_ctx.skey, iv))
 	{
    printf("\n ERROR!! \n");
    return -1;
  
	}

  if (!EVP_EncryptUpdate(x, encrypted_pid_ptr, &encrypted_pid_len, (const unsigned char*)pid_data, pid_len)) 
	{
    printf("\n ERROR!! \n");
    return -2;
  }

  if (!EVP_EncryptFinal_ex(x, encrypted_pid_ptr + encrypted_pid_len, &tmp_len)) 
	{
    printf("\n ERROR!! \n");
    return -3;
	}

  encrypted_pid_len += tmp_len;
  EVP_CIPHER_CTX_free(x);
  return (encrypted_pid_len);

}/*uidai_aes256_encryption*/

int uidai_hmac(unsigned char *pid_xml_ptr, unsigned char *sha256_encrypted)
{
	unsigned char sha256_buff[256];
	unsigned char aes256_encoded_buffer[256];
	unsigned char b64_hmac[256];
	unsigned int len = 0;
  unsigned int tmp_len = 0;

  memset((void *)sha256_buff, 0, sizeof(sha256_buff));
  memset((void *)aes256_encoded_buffer, 0, sizeof(aes256_encoded_buffer));
  memset((void *)b64_hmac, 0, sizeof(b64_hmac));

  uidai_sha256((char *)pid_xml_ptr, sha256_buff);
  len = uidai_aes256_encryption(sha256_buff, 32, aes256_encoded_buffer);
  base64_encode(aes256_encoded_buffer, len, b64_hmac, &tmp_len); 
	memcpy((void *)sha256_encrypted, b64_hmac, tmp_len);
	return(tmp_len);

}/*uidai_hmac*/

unsigned char *get_hmac_tag(void)
{
  int rc = -1;
  unsigned char hmac[512];
  unsigned char b64_hmac[256];
	unsigned char encrypted_hmac[256];
  unsigned char *hmac_tag_ptr = NULL;

	memset((void *)encrypted_hmac, 0, sizeof(encrypted_hmac));
	memset((void *)b64_hmac, 0, sizeof(b64_hmac));

	rc = uidai_hmac(uidai_ctx.pid_xml, b64_hmac);
	/*copying into uidai context buffer*/
	memcpy((void *)uidai_ctx.pid_b64, b64_hmac, rc);

	memset((void *)hmac, 0, sizeof(hmac));

  rc = snprintf(hmac, sizeof(hmac),
		"%s%s%s",
	  "<Hmac>",
	  b64_hmac,
    "</Hmac>");

  hmac_tag_ptr = (char *)malloc(rc);
	memset((void *)hmac_tag_ptr, 0, rc);

	memcpy((void *)hmac_tag_ptr, hmac, rc);
	return(hmac_tag_ptr);

}/*get_hmac_tag*/

int get_pv_attr(unsigned char *pv_attr_ptr)
{
  int rc = 0;
  unsigned char attr_buff[256];
  unsigned int offset = 0;

	memset((void *)attr_buff, 0, sizeof(attr_buff));

  if(uidai_ctx.demo.pv_demographic.otp.is_present)
	{
    rc = snprintf((char *)&attr_buff[offset], sizeof(attr_buff),	
				 "%s%s%s", 
				 "otp=\"",
			   uidai_ctx.demo.pv_demographic.otp.value,
			   "\"");	 
		offset += rc;
	}

  if(uidai_ctx.demo.pv_demographic.pin.is_present)
	{
    rc = snprintf((char *)&attr_buff[offset], sizeof(attr_buff),	
				 "%s%s%s", 
				 " pin=\"",
			   uidai_ctx.demo.pv_demographic.pin.value,
			   "\"");	 
		offset += rc;
	}
  
  memcpy((void *)pv_attr_ptr, attr_buff, offset);
  return(offset);

}/*get_pv_attr*/

int get_bio_attr(unsigned char *bio_attr_ptr)
{
  int rc = 0;
  unsigned char attr_buff[256];
  unsigned int offset = 0;

	memset((void *)attr_buff, 0, sizeof(attr_buff));

  if(uidai_ctx.demo.bio_demographic[0].type.is_present)
	{
    rc = snprintf((char *)&attr_buff[offset], sizeof(attr_buff),	
				 "%s%s%s", 
				 "type=\"",
			   uidai_ctx.demo.bio_demographic[0].type.value,
			   "\"");	 
		offset += rc;
	}

  if(uidai_ctx.demo.bio_demographic[0].posh.is_present)
	{
    rc = snprintf((char *)&attr_buff[offset], sizeof(attr_buff),	
				 "%s%s%s", 
				 " posh=\"",
			   uidai_ctx.demo.bio_demographic[0].posh.value,
			   "\"");	 
		offset += rc;
	}
 
  memcpy((void *)bio_attr_ptr, attr_buff, offset);
  return(offset);

}/*get_bio_attr*/


int get_pfa_attr(unsigned char *pfa_attr_ptr)
{
  int rc = 0;
  unsigned char attr_buff[256];
  unsigned int offset = 0;

	memset((void *)attr_buff, 0, sizeof(attr_buff));

  if(uidai_ctx.demo.pfa_demographic.ms.is_present)
	{
    rc = snprintf((char *)&attr_buff[offset], sizeof(attr_buff),	
				 "%s%s%s", 
				 "ms=\"",
			   uidai_ctx.demo.pfa_demographic.ms.value,
			   "\"");	 
		offset += rc;
	}

  if(uidai_ctx.demo.pfa_demographic.mv.is_present)
	{
    rc = snprintf((char *)&attr_buff[offset], sizeof(attr_buff),	
				 "%s%s%s", 
				 "mv=\"",
			   uidai_ctx.demo.pfa_demographic.mv.value,
			   "\"");	 
		offset += rc;
	}
 	
  if(uidai_ctx.demo.pfa_demographic.av.is_present)
	{
    rc = snprintf((char *)&attr_buff[offset], sizeof(attr_buff),	
				 "%s%s%s", 
				 "av=\"",
			   uidai_ctx.demo.pfa_demographic.av.value,
			   "\"");	 
		offset += rc;
	}

  if(uidai_ctx.demo.pfa_demographic.lav.is_present)
	{
    rc = snprintf((char *)&attr_buff[offset], sizeof(attr_buff),	
				 "%s%s%s", 
				 "lav=\"",
			   uidai_ctx.demo.pfa_demographic.lav.value,
			   "\"");	 
		offset += rc;
	}

  if(uidai_ctx.demo.pfa_demographic.lmv.is_present)
	{
    rc = snprintf((char *)&attr_buff[offset], sizeof(attr_buff),	
				 "%s%s%s", 
				 "lmv=\"",
			   uidai_ctx.demo.pfa_demographic.lmv.value,
			   "\"");	 
		offset += rc;
	}

	memcpy((void *)pfa_attr_ptr, attr_buff, offset);
	return(offset);

}/*get_pfa_attr*/

int get_pa_attr(unsigned char *pa_attr_ptr)
{
  int rc = 0;
  unsigned char pa_attr_buff[256];
  unsigned int offset = 0;

	memset((void *)pa_attr_buff, 0, sizeof(pa_attr_buff));

  if(uidai_ctx.demo.pa_demographic.ms.is_present)
	{
    rc = snprintf((char *)&pa_attr_buff[offset], sizeof(pa_attr_buff),	
				 "%s%s%s", 
				 "ms=\"",
			   uidai_ctx.demo.pa_demographic.ms.value,
			   "\"");	 
		offset += rc;
	}

  if(uidai_ctx.demo.pa_demographic.co.is_present)
	{
    rc = snprintf((char *)&pa_attr_buff[offset], sizeof(pa_attr_buff),	
				 "%s%s%s", 
				 " co=\"",
			   uidai_ctx.demo.pa_demographic.co.value,
			   "\"");	 
		offset += rc;
	}

  if(uidai_ctx.demo.pa_demographic.house.is_present)
	{
    rc = snprintf((char *)&pa_attr_buff[offset], sizeof(pa_attr_buff),	
				 "%s%s%s", 
				 " house=\"",
			   uidai_ctx.demo.pa_demographic.house.value,
			   "\"");
		offset += rc;
	}

  if(uidai_ctx.demo.pa_demographic.street.is_present)
	{
    rc = snprintf((char *)&pa_attr_buff[offset], sizeof(pa_attr_buff),	
				 "%s%s%s", 
				 " street=\"",
			   uidai_ctx.demo.pa_demographic.street.value,
			   "\"");
		offset += rc;
	}
    	
  if(uidai_ctx.demo.pa_demographic.lm.is_present)
	{
    rc = snprintf((char *)&pa_attr_buff[offset], sizeof(pa_attr_buff),	
				 "%s%s%s", 
				 " lm=\"",
			   uidai_ctx.demo.pa_demographic.lm.value,
			   "\"");
		offset += rc;
	}

  if(uidai_ctx.demo.pa_demographic.loc.is_present)
	{
    rc = snprintf((char *)&pa_attr_buff[offset], sizeof(pa_attr_buff),	
				 "%s%s%s", 
				 " loc=\"",
			   uidai_ctx.demo.pa_demographic.loc.value,
			   "\"");
		offset += rc;
	}

  if(uidai_ctx.demo.pa_demographic.vtc.is_present)
	{
    rc = snprintf((char *)&pa_attr_buff[offset], sizeof(pa_attr_buff),	
				 "%s%s%s", 
				 " vtc=\"",
			   uidai_ctx.demo.pa_demographic.vtc.value,
			   "\"");
		offset += rc;
	}

  if(uidai_ctx.demo.pa_demographic.subdist.is_present)
	{
    rc = snprintf((char *)&pa_attr_buff[offset], sizeof(pa_attr_buff),	
				 "%s%s%s", 
				 " subdist=\"",
			   uidai_ctx.demo.pa_demographic.subdist.value,
			   "\"");
		offset += rc;
	}

  if(uidai_ctx.demo.pa_demographic.state.is_present)
	{
    rc = snprintf((char *)&pa_attr_buff[offset], sizeof(pa_attr_buff),	
				 "%s%s%s", 
				 " state=\"",
			   uidai_ctx.demo.pa_demographic.state.value,
			   "\"");
		offset += rc;
	}

  if(uidai_ctx.demo.pa_demographic.pc.is_present)
	{
    rc = snprintf((char *)&pa_attr_buff[offset], sizeof(pa_attr_buff),	
				 "%s%s%s", 
				 " pc=\"",
			   uidai_ctx.demo.pa_demographic.pc.value,
			   "\"");
		offset += rc;
	}

  if(uidai_ctx.demo.pa_demographic.po.is_present)
	{
    rc = snprintf((char *)&pa_attr_buff[offset], sizeof(pa_attr_buff),	
				 "%s%s%s", 
				 " po=\"",
			   uidai_ctx.demo.pa_demographic.po.value,
			   "\"");
		offset += rc;
	}
	memcpy((void *)pa_attr_ptr, pa_attr_buff, offset);
	return(offset);
 	
}/*get_pa_attr*/

int get_pi_attr(unsigned char *pi_attr_ptr)
{
  int rc = 0;
  unsigned char pi_attr_buff[256];
  unsigned int offset = 0;

	memset((void *)pi_attr_buff, 0, sizeof(pi_attr_buff));

  if(uidai_ctx.demo.pi_demographic.ms.is_present)
	{
    rc = snprintf((char *)&pi_attr_buff[offset], sizeof(pi_attr_buff),	
				 "%s%s%s", 
				 "ms=\"",
			   uidai_ctx.demo.pi_demographic.ms.value,
			   "\"");	 
		offset += rc;
	}

  if(uidai_ctx.demo.pi_demographic.mv.is_present)
	{
    rc = snprintf((char *)&pi_attr_buff[offset], sizeof(pi_attr_buff),	
				 "%s%s%s", 
				 " mv=\"",
			   uidai_ctx.demo.pi_demographic.mv.value,
			   "\"");	 
		offset += rc;
	}

  if(uidai_ctx.demo.pi_demographic.name.is_present)
	{
    rc = snprintf((char *)&pi_attr_buff[offset], sizeof(pi_attr_buff),	
				 "%s%s%s", 
				 " name=\"",
			   uidai_ctx.demo.pi_demographic.name.value,
			   "\"");
		offset += rc;
	}

  if(uidai_ctx.demo.pi_demographic.lname.is_present)
	{
    rc = snprintf((char *)&pi_attr_buff[offset], sizeof(pi_attr_buff),	
				 "%s%s%s", 
				 " lname=\"",
			   uidai_ctx.demo.pi_demographic.lname.value,
			   "\"");
		offset += rc;
	}
    	
  if(uidai_ctx.demo.pi_demographic.gender.is_present)
	{
    rc = snprintf((char *)&pi_attr_buff[offset], sizeof(pi_attr_buff),	
				 "%s%s%s", 
				 " gender=\"",
			   uidai_ctx.demo.pi_demographic.gender.value,
			   "\"");
		offset += rc;
	}

  if(uidai_ctx.demo.pi_demographic.dob.is_present)
	{
    rc = snprintf((char *)&pi_attr_buff[offset], sizeof(pi_attr_buff),	
				 "%s%s%s", 
				 " dob=\"",
			   uidai_ctx.demo.pi_demographic.dob.value,
			   "\"");
		offset += rc;
	}

  if(uidai_ctx.demo.pi_demographic.dobt.is_present)
	{
    rc = snprintf((char *)&pi_attr_buff[offset], sizeof(pi_attr_buff),	
				 "%s%s%s", 
				 " dobt=\"",
			   uidai_ctx.demo.pi_demographic.dobt.value,
			   "\"");
		offset += rc;
	}

  if(uidai_ctx.demo.pi_demographic.age.is_present)
	{
    rc = snprintf((char *)&pi_attr_buff[offset], sizeof(pi_attr_buff),	
				 "%s%s%s", 
				 " age=\"",
			   uidai_ctx.demo.pi_demographic.age.value,
			   "\"");
		offset += rc;
	}

  if(uidai_ctx.demo.pi_demographic.phone.is_present)
	{
    rc = snprintf((char *)&pi_attr_buff[offset], sizeof(pi_attr_buff),	
				 "%s%s%s", 
				 " phone=\"",
			   uidai_ctx.demo.pi_demographic.phone.value,
			   "\"");
		offset += rc;
	}

  if(uidai_ctx.demo.pi_demographic.email.is_present)
	{
    rc = snprintf((char *)&pi_attr_buff[offset], sizeof(pi_attr_buff),	
				 "%s%s%s", 
				 " email=\"",
			   uidai_ctx.demo.pi_demographic.phone.value,
			   "\"");
		offset += rc;
	}

	memcpy((void *)pi_attr_ptr, pi_attr_buff, offset);
	return(offset);

}/*get_pi_attr*/


int get_pid_xml(unsigned char *pid_xml_ptr)
{
  int    rc = -1;
	unsigned int offset = 0;
  unsigned char   pid_buffer[256];
  unsigned char   ts[32];
	unsigned char   px[512];
	unsigned char   pi_attr[128];
	unsigned char   pa_attr[128];
	unsigned char   pfa_attr[128];
	unsigned char   bio_attr[128];
	unsigned char   pv_attr[128];

  time_t curr_time;
  struct tm *local_time;

  /*Retrieving the current time*/
  curr_time = time(NULL);
  local_time = localtime(&curr_time);
  snprintf(ts, sizeof(ts),
			"%04d-%02d-%02dT%02d:%02d:%02d", 
			local_time->tm_year+1900, 
      local_time->tm_mon+1, 
			local_time->tm_mday, 
      local_time->tm_hour, 
			local_time->tm_min, 
			local_time->tm_sec);
	
	memset((void *)px, 0, sizeof(px));
  rc = 0;

	if(uidai_ctx.demo.is_pi_present)
	{
		get_pi_attr(pi_attr);
    rc = snprintf((char *)&px[offset], sizeof(px),
		     "%s%s%s",
		     "\n<Demo>\n<Pi ",
				 pi_attr,
				 "/>");		 
    offset += rc;
	}

	if(uidai_ctx.demo.is_pa_present)
	{
    get_pa_attr(pa_attr);

		if(uidai_ctx.demo.is_pi_present)
		{
      rc = snprintf((char *)&px[offset], sizeof(px),
		       "%s%s%s",
		       "\n<Pa ",
				   pa_attr,
				   "/>");
		}
		else
		{
      rc = snprintf((char *)&px[offset], sizeof(px),
		       "%s%s%s",
		       "<Demo>\n<Pa ",
				   pa_attr,
				   "/>");
		}			
    offset += rc;
	}

	if(uidai_ctx.demo.is_pfa_present)
	{
		get_pfa_attr(pfa_attr);

		if(uidai_ctx.demo.is_pi_present ||
			 uidai_ctx.demo.is_pa_present)
		{	
		  rc = snprintf((char *)&px[offset], sizeof(px),
				 "%s%s%s",
				 "\n<Pfa ",
				 pfa_attr,
				 "/>");
		}
		else
		{
		  rc = snprintf((char *)&px[offset], sizeof(px),
				 "%s%s%s",
				 "\n<Demo>\n<Pfa ",
				 pfa_attr,
				 "/>");
	  }
    offset += rc;
	}
  /*Closing the end tag od Demo*/
	rc = snprintf((char *)&px[offset], sizeof(px),
			 "%s",
			 "\n</Demo>\n");
	offset += rc;

	if(uidai_ctx.demo.is_bio_present)
	{
		get_bio_attr(bio_attr);

		if(uidai_ctx.demo.is_pi_present  ||
			 uidai_ctx.demo.is_pfa_present ||
			 uidai_ctx.demo.is_pa_present)
		{
      rc = snprintf((char *)&px[offset], sizeof(px),
				   "%s%s%s%s%s"
					 "%s%s%s",
				   "</Demo>\n",
					 "<Bios>\n",
					 "<Bio ",
					 bio_attr,
					 ">",
					 /*Bio Value to be updated*/
					 "\n",
					 "</Bio>\n",
					 "</Bios>\n");	 
		}
		else
		{
		  rc = snprintf((char *)&px[offset], sizeof(px),
			  	 "%s%s%s%s%s",
				   "<Bios>\n",
				   "<Bio ",
				   bio_attr,
				   "</Bio>\n",
				   "</Bios>");
		}
		offset += rc;
	}

	if(uidai_ctx.demo.is_pv_present)
	{
    get_pv_attr(pv_attr);
    
    rc = snprintf((char *)&px[offset], sizeof(px),
		     "%s%s%s",
		     "<Pv ",
		     pv_attr,
		     "/>\n");		 
	  offset += rc;
	}

  memset((void *)pid_buffer, 0, sizeof(pid_buffer));
  rc = snprintf(pid_buffer, sizeof(pid_buffer),
	  	 "%s%s%s%s%s"
		   "%s%s%s%s%s",
			 "<?xml  version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\" ?>\n",
		   "<Pid xmlns=\"http://www.uidai.gov.in/authentication/uid-auth-request-data/1.0\"",
		   " ts=\"",
		   ts,
		   "\"",
		   " ver=\"",
		   uidai_ctx.pid_ver,
		   "\">",
		   px,
			 "</Pid>");

	 fprintf(stderr, "pid_buffer is %s\n", pid_buffer);
   memcpy((void *)pid_xml_ptr, pid_buffer, rc);
	 /*copying into the uidai context buffer*/
	 memset((void *)uidai_ctx.pid_xml, 0, sizeof(uidai_ctx.pid_xml));
	 memcpy((void *)uidai_ctx.pid_xml, pid_buffer, rc);
	 return(rc);

}/*get_pid_xml*/

int get_encrypted_pid(unsigned char *pid_ptr)
{
  unsigned char pid[512];
  int  pid_len = 0;
  
  pid_len = get_pid_xml(pid);
  pid_len = uidai_aes256_encryption(pid, pid_len, pid_ptr); 	
  
	return(pid_len);
}/*get_encrypted_pid*/

unsigned char *get_data_tag(void)
{
  int rc = -1;
  char pid_data[3048];
	char pid_b64[3048];

	char encrypted_pid[1024];
  char *pid_data_block_ptr = NULL;
  int  len = -1;

	memset((void *)encrypted_pid, 0, sizeof(encrypted_pid));
  len = get_encrypted_pid(encrypted_pid);

  memset((void *)pid_b64, 0, sizeof(pid_b64));
	rc = base64_encode(encrypted_pid, len, pid_b64, &len);
	/*copying pid_xml (base64) into uidai context*/
	memcpy((void *)uidai_ctx.pid_b64, pid_b64, rc);

	memset((void *)pid_data, 0, sizeof(pid_data));
	rc = snprintf(pid_data, sizeof(pid_data),
			"%s%s%s",
			"<Data type=\"X\">",
			pid_b64,
			"</Data>");

  pid_data_block_ptr = (char *)malloc(rc);
	memset((void *)pid_data_block_ptr, 0, rc);

	memcpy((void *)pid_data_block_ptr, pid_data, rc);
	return(pid_data_block_ptr);

}/*get_data_tag*/


int get_ci(unsigned char *ci_ptr)
{
  memcpy((void *)ci_ptr, uidai_ctx.certificate_expiry, strlen((const char *)uidai_ctx.certificate_expiry));
  return(0);

}/*get_ci*/

int get_skey(unsigned char *skey_ptr)
{
	/*private key is nothing but 32-bytes random numbers*/
	unsigned char private_key[32];
  int  rc = -1;
	FILE *fp = NULL;
	unsigned char encrypted_private_key[512];
	unsigned char b64_buffer[512];

  int  len = -1;

  memset((void *)private_key, 0, sizeof(private_key));

  fp = fopen("/dev/urandom", "r");
	if(NULL == fp)
	{
		fprintf(stderr, "Failed to open /dev/urandon file\n");
    return(-1);		
	}
  rc = fread(private_key, 1, 32, fp);
  fclose(fp);

	memset((void *)uidai_ctx.skey, 0, 32);
  memcpy((void *)uidai_ctx.skey, private_key, 32);

	memset((void *)encrypted_private_key, 0, sizeof(encrypted_private_key));

  /*Now encrypting this private key using 2048-bits RSA Public Key*/
	len = RSA_public_encrypt(32, 
			                     private_key, 
			                     encrypted_private_key, 
			                     uidai_ctx.rsa,
			                     RSA_PKCS1_PADDING);

  memset((void *)b64_buffer, 0, sizeof(b64_buffer));
 
	base64_encode(encrypted_private_key,
               len,
               b64_buffer,
               &len);
 
	memcpy((void *)skey_ptr, b64_buffer, len);

	return(len);
}/*get_skey*/


unsigned char *get_skey_tag(void)
{
  unsigned char *skey_ptr = NULL;
  unsigned char skey_buffer[1024];
  int  rc = -1;
  unsigned char ci[12];
	unsigned char session_key[1024];
  char bufExpiryStr[12];
	char *expiry=NULL;

	/*Initializing auto variables*/
	memset((void *)ci, 0, sizeof(ci));
	memset((void *)session_key, 0, sizeof(session_key));

	/*populating the auto variables*/
	get_ci(ci);
	get_skey(session_key);

  memset((void *)skey_buffer, 0, sizeof(skey_buffer));

  rc = snprintf(skey_buffer, sizeof(skey_buffer),
		"%s%s%s%s%s"
		"%s",
	  "<Skey",
	  " ci=\"", ci, "\">",
	  session_key,
		"</Skey>");

  skey_ptr = (unsigned char *)malloc(rc);
	memset((void *)skey_ptr, 0, rc);
	memcpy((void *)skey_ptr, skey_buffer, rc);

	return(skey_ptr);
}/*get_skey_tag*/


int get_udc(unsigned char *udc_ptr)
{
  unsigned char *value_ptr = "SampleClientDemo";
  memcpy((void *)udc_ptr, value_ptr, strlen((const char *)value_ptr));
  return(0);

}/*get_udc*/

int get_fdc(unsigned char *fdc_ptr)
{
  unsigned char *value_ptr = "NC";
  memcpy((void *)fdc_ptr, value_ptr, strlen((const char *)value_ptr));
  return(0);

}/*get_fdc*/

int get_idc(unsigned char *idc_ptr)
{
  unsigned char *value_ptr = "NA";
  memcpy((void *)idc_ptr, value_ptr, strlen((const char *)value_ptr));
  return(0);

}/*get_idc*/

int get_pip(unsigned char *pip_ptr)
{
  unsigned char *value_ptr = "127.0.0.1";
  memcpy((void *)pip_ptr, value_ptr, strlen((const char *)value_ptr));
  return(0);

}/*get_pip*/

int get_lot(unsigned char *lot_ptr)
{
  unsigned char *value_ptr = "P";
  memcpy((void *)lot_ptr, value_ptr, strlen((const char *)value_ptr));
  return(0);

}/*get_lot*/

int get_lov(unsigned char *lov_ptr)
{
  char *value_ptr = "500008";
  memcpy((void *)lov_ptr, value_ptr, strlen((const char *)value_ptr));
  return(0);

}/*get_lov*/

unsigned char *get_meta_tag(void)
{
  unsigned char meta_buffer[256];
  unsigned char *meta_ptr = NULL;
	int  rc = -1;
	/*Auto Variables for Uses Attributes*/
  unsigned char udc[32];
  unsigned char fdc[32];
  unsigned char idc[32];
  unsigned char pip[32];
  unsigned char lot[32];
  unsigned char lov[32];

  /*Initialization of auto variables*/
  memset((void *)udc,  0, sizeof(udc));
  memset((void *)fdc,  0, sizeof(fdc));
  memset((void *)idc,  0, sizeof(idc));
  memset((void *)pip,  0, sizeof(pip));
  memset((void *)lot,  0, sizeof(lot));
  memset((void *)lov,  0, sizeof(lov));

	/*Populating Uses Attribute value*/
	get_udc(udc);
	get_fdc(fdc);
	get_idc(idc);
	get_pip(pip);
	get_lot(lot);
	get_lov(lov);

	memset((void *)meta_buffer, 0, sizeof(meta_buffer));
  
	rc = snprintf(meta_buffer, sizeof(meta_buffer),
			"%s%s%s%s%s"
			"%s%s%s%s%s"
			"%s%s%s%s%s"
			"%s%s%s%s",
			"<Meta",
		  " udc=\"", udc,  "\"",
		  " fdc=\"", fdc,  "\"",
			" idc=\"", idc, "\"",
			" pip=\"", pip, "\"",
		  " lot=\"", lot,  "\"",
		  " lov=\"", lov, "\"/>");
  
	meta_ptr = (unsigned char *)malloc(rc);
	memset((void *)meta_ptr, 0, rc);
	memcpy((void *)meta_ptr, meta_buffer, rc);
  return(meta_ptr);

}/*get_meta_tag*/


int get_pi(unsigned char *pi_ptr)
{
  memcpy((void *)pi_ptr, "y", 3);
  return(0);

}/*get_pi*/

int get_pa(unsigned char *pa_ptr)
{
  memcpy((void *)pa_ptr, "n", 3);
  return(0);

}/*get_pa*/

int get_pfa(unsigned char *pfa_ptr)
{
  memcpy((void *)pfa_ptr, "n", 3);
  return(0);

}/*get_pfa*/

int get_bio(unsigned char *bio_ptr)
{
  memcpy((void *)bio_ptr, "n", 3);
  return(0);

}/*get_bio*/

int get_bt(unsigned char *bt_ptr)
{
  memcpy((void *)bt_ptr, "n", 3);
  return(0);

}/*get_bt*/

int get_pin(unsigned char *pin_ptr)
{
  memcpy((void *)pin_ptr, "n", 3);
  return(0);

}/*get_pin*/

int get_otp(unsigned char *otp_ptr)
{
  memcpy((void *)otp_ptr, "n", 3);
  return(0);

}/*get_otp*/

unsigned char *get_uses_tag(void)
{
  unsigned char uses_buffer[256];
  unsigned char *uses_ptr = NULL;
	int  rc = -1;
	/*Auto Variables for Uses Attributes*/
  unsigned char pi[4];
  unsigned char pa[4];
  unsigned char pfa[4];
  unsigned char bio[4];
  unsigned char bt[4];
  unsigned char pin[4];
  unsigned char otp[4];

  /*Initialization of auto variables*/
  memset((void *)pi,  0, sizeof(pi));
  memset((void *)pa,  0, sizeof(pa));
  memset((void *)pfa, 0, sizeof(pfa));
  memset((void *)bio, 0, sizeof(bio));
  memset((void *)bt,  0, sizeof(bt));
  memset((void *)pin, 0, sizeof(pin));
  memset((void *)otp, 0, sizeof(otp));

	/*Populating Uses Attribute value*/
	get_pi(pi);
	get_pa(pa);
	get_pfa(pfa);
	get_bio(bio);
	get_bt(bt);
	get_pin(pin);
	get_otp(otp);

	memset((void *)uses_buffer, 0, sizeof(uses_buffer));
  
	rc = snprintf(uses_buffer, sizeof(uses_buffer),
			"%s%s%s%s%s"
			"%s%s%s%s%s"
			"%s%s%s%s%s"
			"%s%s%s%s",
			"<Uses",
		  " pi=\"",  pi,  "\"",
		  " pa=\"",  pa,  "\"",
			" pfa=\"", pfa, "\"",
			" bio=\"", bio, "\"",
		  //" bt=\"",  bt,  "\"",
		  " pin=\"", pin, "\"",
		  " otp=\"", otp, "\"/>");	
  
	uses_ptr = (unsigned char *)malloc(rc);
	memset((void *)uses_ptr, 0, rc);
	memcpy((void *)uses_ptr, uses_buffer, rc);
  return(uses_ptr);

}/*get_uses_tag*/


void get_uid(unsigned char *uid_ptr)
{
	char *id_ptr ="999999990019";
  memcpy((void *)uid_ptr, id_ptr, strlen((const char *)id_ptr)); 	
}/*get_uid*/


void get_tid(unsigned char *tid_ptr)
{
	unsigned char *device_id_ptr ="public";
  memcpy((void *)tid_ptr, device_id_ptr, strlen((const char *)device_id_ptr)); 	
}/*get_tid*/


void get_ac(unsigned char *aua_code_ptr)
{
	unsigned char *ac_ptr ="public";
  memcpy((void *)aua_code_ptr, ac_ptr, strlen((const char *)ac_ptr)); 	
}/*get_ac*/

void get_sa(unsigned char *sub_aua_code_ptr)
{
	unsigned char *sa_ptr ="public";
  memcpy((void *)sub_aua_code_ptr, sa_ptr, strlen((const char *)sa_ptr)); 	
}/*get_sa*/

void get_version(unsigned char *version_ptr)
{
	unsigned char *ver_ptr ="1.6";
  memcpy((void *)version_ptr, ver_ptr, strlen((const char *)ver_ptr)); 	
}/*get_version*/

void get_transaction(unsigned char *transaction_ptr)
{
	unsigned char *txn_ptr ="SampleClientDemo";
  memcpy((void *)transaction_ptr, txn_ptr, strlen((const char *)txn_ptr)); 	
}/*get_transaction*/


void get_aua_license(unsigned char *asa_license_ptr)
{
	unsigned char *asa_ptr = AUA_KEY;
  memcpy((void *)asa_license_ptr, asa_ptr, strlen((const char *)asa_ptr)); 	
}/*get_asa_license*/

unsigned char *get_auth_attribute(void)
{
  unsigned char *auth_attribute_ptr = NULL;
  unsigned char auth_attr_buff[1024];
  int  rc = -1;
  unsigned char uid[64];
	unsigned char tid[64];
	unsigned char ac[64];
	unsigned char sa[64];
	unsigned char version[8];
	unsigned char transaction[64];
	unsigned char aua_license_key[64];
	
	/*Initializing the auto variables*/
	memset((void *)uid, 0, sizeof(uid));
	memset((void *)tid, 0, sizeof(tid));
	memset((void *)ac, 0, sizeof(ac));
	memset((void *)sa, 0, sizeof(sa));
	memset((void *)version, 0, sizeof(version));
	memset((void *)transaction, 0, sizeof(transaction));
	memset((void *)aua_license_key, 0, sizeof(aua_license_key));

	/*Populating the Auto Variables*/
	get_uid(uid);
	get_tid(tid);
	get_ac(ac);
	get_sa(sa);
	get_version(version);
	get_transaction(transaction);
	get_aua_license(aua_license_key);
  	
  memset((void *)auth_attr_buff, 0, sizeof(auth_attr_buff));
  rc = snprintf(auth_attr_buff, sizeof(auth_attr_buff),
		"%s%s%s"
		"%s%s%s"
		"%s%s%s"
		"%s%s%s"
		"%s%s%s"
		"%s%s%s"
		"%s%s%s",
	  " uid=\"", uid,             "\"",
		" tid=\"", tid,             "\"",
		" ac=\"",  ac,              "\"",
		" sa=\"",  sa,              "\"",
		" ver=\"", version,         "\"",
		" txn=\"", transaction,     "\"",
		" lk=\"",  aua_license_key, "\"");

  auth_attribute_ptr = (unsigned char *)malloc(rc);

  memset((void *)auth_attribute_ptr, 0, rc);

  memcpy((void *)auth_attribute_ptr, auth_attr_buff, rc);
  return(auth_attribute_ptr);

}/*get_auth_attribute*/

int build_auth_xml(unsigned char *auth_xml_ptr)
{
  unsigned char auth_xml_buff[4048];
  int rc = -1;
	unsigned char *uses_tag_ptr = NULL;
	unsigned char *meta_tag_ptr = NULL;
	unsigned char *skey_tag_ptr = NULL;
	unsigned char *data_tag_ptr = NULL;
	unsigned char *hmac_tag_ptr = NULL;
  unsigned char *auth_attr    = NULL;

	uses_tag_ptr = get_uses_tag();
	meta_tag_ptr = get_meta_tag();
	skey_tag_ptr = get_skey_tag();
	data_tag_ptr = get_data_tag();
	hmac_tag_ptr = get_hmac_tag();
  auth_attr    = get_auth_attribute();

  memset((void *)auth_xml_buff, 0, sizeof(auth_xml_buff));

  rc = snprintf(auth_xml_buff, sizeof(auth_xml_buff),
		"%s%s%s%s%s"
		"%s%s%s%s%s"
		"%s%s%s%s%s"
		"%s",
		"<?xml version=\"1.0\" encoding=\"UTF-8\" ?>",
		"\n",
		/*The root element of Auth XML*/
	  "<Auth xmlns=\"http://www.uidai.gov.in/authentication/uid-auth-request/1.0\"",
		auth_attr,
    ">\n",
		/*Uses Tag*/
    uses_tag_ptr,
		"\n",
		/*Meta tag*/
		meta_tag_ptr,
		"\n",
		/*Session Key*/
		skey_tag_ptr,
		"\n",
		/*PID Encrypted Data*/
		data_tag_ptr,
		"\n",
		/*SHA-256 of PID XML*/
		hmac_tag_ptr,
		"\n",
		"</Auth>");

	free(auth_attr);
	free(uses_tag_ptr);
	free(meta_tag_ptr);
	free(skey_tag_ptr);
	free(data_tag_ptr);
	free(hmac_tag_ptr);

  memcpy((void *)auth_xml_ptr, auth_xml_buff, rc);
	/*copying Auth xml into uidai context*/
	memcpy((void *)uidai_ctx.auth_xml, auth_xml_buff, rc);

  return(rc);

}/*build_auth_xml*/


int uidai_init(const unsigned char *public_cer_file, const unsigned char *private_cer_file)
{
  X509 *x;
  FILE *fp;
  ERR_load_crypto_strings();

  fp = fopen(public_cer_file,"r");
  assert(fp != NULL);

	x = PEM_read_X509(fp, NULL, 0, NULL);
  fclose(fp);

  uidai_ctx.epkey = X509_get_pubkey(x);

  /*For openssl-1.1.0e*/
  uidai_ctx.rsa = EVP_PKEY_get1_RSA(uidai_ctx.epkey);

	memcpy((void *)uidai_ctx.public_certificate_file,  public_cer_file,  strlen((const char *)public_cer_file));
	memcpy((void *)uidai_ctx.private_certificate_file, private_cer_file, strlen((const char *)private_cer_file));
  X509_free(x);

}/*uidai_init*/

int uidai_main(const unsigned char *public, const unsigned char *private, unsigned char *auth_xml_ptr)
{
  memcpy((void *)uidai_ctx.public_certificate_file, public, strlen((const char *)public));
  memcpy((void *)uidai_ctx.private_certificate_file, private, strlen((const char *)public));

	uidai_init(public, private);
  

  build_auth_xml(auth_xml_ptr);	
	RSA_free(uidai_ctx.rsa);
  EVP_PKEY_free(uidai_ctx.epkey);	
	return(0);

}/*uidai_main*/
#endif /*__UIDAI_C__*/
