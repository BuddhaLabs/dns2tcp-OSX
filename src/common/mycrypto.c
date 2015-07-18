/*
** Copyright (C) 2006 Olivier DEMBOUR
** $Id: mycrypto.c,v 1.4.4.3 2010/02/10 15:21:54 collignon Exp $
**
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License as published by
** the Free Software Foundation; either version 2 of the License, or
** (at your option) any later version.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with This program; if not, write to the Free Software
** Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#ifndef _WIN32
#include <openssl/hmac.h>
#include <openssl/evp.h>
#else
#include "mywin32.h"
#include <wincrypt.h>
#define	EVP_MAX_MD_SIZE 64
#endif


static const char charset[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

void	alphanum_random(char *buffer, int len)
{
  buffer[len] = 0;

  while (len--)
    buffer[len] = charset[rand() % (sizeof(charset)-1)];
}

#ifdef _WIN32
static HCRYPTHASH	sha1_start(void *data, unsigned int data_size)
{
  HCRYPTHASH		hash;
  static HCRYPTPROV	prov = 0;

  hash = 0;
  
  if (!prov && !CryptAcquireContext(&prov, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
    {
      fprintf(stderr, "error: failed to acquire cryptoapi context (0x%lx)\n",
	      GetLastError());
      return -1;
    }
  
  if (CryptCreateHash(prov, CALG_SHA1, 0, 0, &hash))
    {
      if (!CryptHashData(hash, data, data_size, 0))
	{
	  fprintf(stderr, "error: failed to hash init data (0x%lx)\n", GetLastError());
	  CryptDestroyHash(hash);
	  return 0;
	}
      
    }
  return hash;
}

static void sha1_update(HCRYPTHASH hash, void *data, unsigned int data_size)
{
  CryptHashData(hash, data, data_size, 0);
}

static void	sha1_final(HCRYPTHASH hash, void *digest)
{
  DWORD		size;
  
  size = 20;
  CryptGetHashParam(hash, HP_HASHVAL, digest, &size, 0);
  CryptDestroyHash(hash);
}

static int	hmac_win(void *key, unsigned int key_size,
			 void *input, unsigned int in_size,
			 void *output, unsigned int *out_size)
{
  int		i;
  HCRYPTHASH	hash;
  char		digest[20];
  char		hmac_key[128];
  int		pad[32];
  
  // prepare key
  if (key_size <= 64)
    memcpy(hmac_key, key, key_size);
  else
    {
      if (!(hash = sha1_start(key, key_size)))
	return -1;
      sha1_final(hash, hmac_key);
    }
  if (key_size < 128)
    memset(hmac_key + key_size, 0, 128-key_size);
  
  // input padding
  for (i=0; i<32; ++i)
    pad[i] = 0x36363636 ^ ((int *)hmac_key)[i];
  if (!(hash = sha1_start(pad, 64)))
    return -1;
  // HMAC data
  sha1_update(hash, input, in_size);
  sha1_final(hash, digest);
  
  // output padding
  for (i=0; i<32; ++i)
    pad[i] = 0x5c5c5c5c ^ ((int *)hmac_key)[i];
  if (!(hash = sha1_start(pad, 64)))
    return -1;
  sha1_update(hash, digest, 20);
  sha1_final(hash, output);
  
  *out_size = 20;
  
  return 0;
}
#endif


/**
 * @brief interface to an HMAC function
 * @param[in] input data to sign
 * @param[in] len input len
 * @param[in] key key for HMAC
 * @param[out] output output
 * @param[in] max_len max output len
 **/

int		sign_challenge(char *input, int len, 
			       char *key, char *output, int max_len)
{
  unsigned int	output_len;
  char		buffer[EVP_MAX_MD_SIZE];
  int		i=0;

#ifndef _WIN32
  HMAC(EVP_sha1(),
       key ? key : "",
       key ? strlen(key) : 0, 
       (unsigned char *)input, len,
       (unsigned char *)&buffer,
       &output_len);
#else
  if (hmac_win(key ? key : "", key ? strlen(key) : 0,
	       input, len, buffer, &output_len))
    return 0;
#endif

  if (output_len*2 < max_len)
    {
      for (i = 0; i < output_len; i++) 
	sprintf(output + 2*i, "%.2X", buffer[i]&0xff);
      output[2*i] = 0;
    }
  return (2*i);
}


