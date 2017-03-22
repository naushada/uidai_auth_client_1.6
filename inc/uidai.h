#ifndef __UIDAI_H__
#define __UIDAI_H__

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/x509.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/bn.h>
#include <openssl/asn1.h>
#include <openssl/pkcs12.h>


typedef struct
{
  unsigned char is_present;
  unsigned char value[64];	
}demographic_tag_t;

typedef struct
{
  demographic_tag_t uid;
  demographic_tag_t tid;
  demographic_tag_t ac;
  demographic_tag_t sa;
  demographic_tag_t ver;
  demographic_tag_t txn;
  demographic_tag_t lk;
}auth_attribute_t;

typedef struct
{
  demographic_tag_t pi;
  demographic_tag_t pfa;
  demographic_tag_t pa;
  demographic_tag_t bio;
  demographic_tag_t bt;
  demographic_tag_t pin;
  demographic_tag_t otp;
}uses_attribute_t;


typedef struct
{
  demographic_tag_t udc;
  demographic_tag_t fdc;
  demographic_tag_t idc;
  demographic_tag_t pip;
  demographic_tag_t lot;
  demographic_tag_t lov;
}meta_attribute_t;

typedef struct
{
  demographic_tag_t ms;
  demographic_tag_t mv;
  demographic_tag_t name;
  demographic_tag_t lname;
  demographic_tag_t lmv;
  demographic_tag_t gender;
  demographic_tag_t dob;
  demographic_tag_t dobt;
  demographic_tag_t age;
  demographic_tag_t phone;
  demographic_tag_t email;
}pi_data_t;

typedef struct
{
  demographic_tag_t ms;
  demographic_tag_t co;
  demographic_tag_t house;
  demographic_tag_t street;
  demographic_tag_t lm;
  demographic_tag_t loc;
  demographic_tag_t vtc;
  demographic_tag_t subdist;
  demographic_tag_t state;
  demographic_tag_t pc;
  demographic_tag_t po;
}pa_data_t;

typedef struct
{
  demographic_tag_t ms;
  demographic_tag_t mv;
  demographic_tag_t av;
  demographic_tag_t lav;
  demographic_tag_t lmv;
}pfa_data_t;

typedef struct
{
  demographic_tag_t type;
  demographic_tag_t posh;
}bio_data_t;

typedef struct
{
  demographic_tag_t otp;
  demographic_tag_t pin;
}pv_data_t;

typedef struct
{
  unsigned char is_pi_present;
  pi_data_t pi_demographic;
  unsigned char is_pfa_present;
  pfa_data_t pfa_demographic;
  unsigned char is_pa_present;
  pa_data_t pa_demographic;
  unsigned char is_bio_present;
	/*There could be morethan 1 Bio present*/
	unsigned char bio_demographic_count;
  bio_data_t bio_demographic[8];
  unsigned char is_pv_present;
  pv_data_t pv_demographic;
}demo_data_t;

typedef struct
{
  unsigned char skey[32];
  unsigned char skey_b64[512];
  unsigned char pid_b64[256];
  unsigned char hmac_b64[256];
	unsigned char pid_xml[256];
	unsigned char pid_ver[4];
  unsigned char auth_xml[5048];

  auth_attribute_t auth_attr;
	uses_attribute_t uses_attr;
	meta_attribute_t meta_attr;
	/*Demographics Data*/
	demo_data_t      demo;
	/*RSA structure*/
	RSA *rsa;
	EVP_PKEY *epkey;
  unsigned char certificate_expiry[16];
  
	unsigned char public_certificate_file[256];
	unsigned char private_certificate_file[256];
	unsigned char password[32];

}uidai_context_t;

int get_ci(unsigned char *ci_ptr);

int get_skey(unsigned char *skey_ptr);

unsigned char *get_skey_tag(void);

int get_udc(unsigned char *udc_ptr);

int get_fdc(unsigned char *fdc_ptr);

int get_idc(unsigned char *idc_ptr);

int get_pip(unsigned char *pip_ptr);

int get_lot(unsigned char *lot_ptr);

int get_lov(unsigned char *lov_ptr);

unsigned char *get_meta_tag(void);

int get_pi(unsigned char *pi_ptr);

int get_pa(unsigned char *pa_ptr);

int get_pfa(unsigned char *pfa_ptr);

int get_bio(unsigned char *bio_ptr);

int get_bt(unsigned char *bt_ptr);

int get_pin(unsigned char *pin_ptr);

int get_otp(unsigned char *otp_ptr);

unsigned char *get_uses_tag(void);

void get_uid(unsigned char *uid_ptr);

void get_tid(unsigned char *tid_ptr);

void get_ac(unsigned char *aua_code_ptr);

void get_sa(unsigned char *sub_aua_code_ptr);

void get_version(unsigned char *version_ptr);

void get_transaction(unsigned char *transaction_ptr);

void get_asa_license(unsigned char *asa_license_ptr);

unsigned char *get_auth_attribute(void);

int build_auth_xml(unsigned char *auth_xml_ptr);

int uidai_sha256(char *pid_xml_ptr, unsigned char *sha256_ptr);

int uidai_aes256_encryption(unsigned char *pid_data, int pid_len, unsigned char *encrypted_pid_ptr);

unsigned char *get_hmac_tag(void);

int get_pv_attr(unsigned char *pv_attr_ptr);

int get_bio_attr(unsigned char *bio_attr_ptr);

int get_pfa_attr(unsigned char *pfa_attr_ptr);

int get_pa_attr(unsigned char *pa_attr_ptr);

int get_pi_attr(unsigned char *pi_attr_ptr);

int get_pid_xml(unsigned char *pid_xml_ptr);

int get_encrypted_pid(unsigned char *pid_ptr);

unsigned char *get_data_tag(void);

int uidai_main(const unsigned char *public_cer, const unsigned char *private_cer, unsigned char *auth_xml_ptr);

int uidai_init(const unsigned char *public_cer_file, const unsigned char *private_cer_file);


#endif /*UIDAI_H__*/
