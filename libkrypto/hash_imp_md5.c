/* This core now looks for MD5 in an underlying crypto library */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#ifdef HASH_MD5

#include "hash_imp_md5.h"
#include "krypto.h"

/* GLUE ROUTINES */

static void *
imp_md5_new ()
{
  MD5_CTX *ctxt;
  ctxt = (MD5_CTX *) malloc (sizeof (MD5_CTX));
  return (void *) ctxt;
}

static void
imp_md5_delete (ctxt)
  void *ctxt;
{
  if (ctxt) free (ctxt);
}

static void
imp_md5_init (ctxt)
  MD5_CTX *ctxt;
{
  MD5_Init(ctxt);
}

static void
imp_md5_update (ctxt, data, len)
  MD5_CTX *ctxt;
  unsigned char *data;
  unsigned len;
{
  MD5_Update(ctxt, data, len);
}

static void
imp_md5_final (ctxt, out)
  MD5_CTX *ctxt;
  unsigned char *out;
{
  MD5_Final(out, ctxt);
}

hash_desc MD5desc =
{
  HASH_ID_MD5,
  "MD5",
  16,
  imp_md5_new,
  imp_md5_init,
  imp_md5_update,
  imp_md5_final,
  imp_md5_delete
};

#endif /* HASH_MD5 */
