/* This glue code now accesses SHA1 through libsrp. */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#include "../libsrp/t_sha.h"
#include "krypto.h"
#include "hash_imp_sha.h"

/* GLUE ROUTINES */

static void *
sha_new ()
{
  SHA1_CTX *ctxt;
  ctxt = (SHA1_CTX *) malloc (sizeof (SHA1_CTX));
  return (void *) ctxt;
}

static void
sha_delete (ctxt)
  void *ctxt;
{
  if (ctxt) free (ctxt);
}

static void
sha_init (ctxt)
  SHA1_CTX *ctxt;
{
  SHA1Init (ctxt);
}

static void
sha_update (ctxt, data, len)
  SHA1_CTX *ctxt;
  unsigned char *data;
  unsigned len;
{
  SHA1Update (ctxt, data, len);
}

static void
sha_final (ctxt, out)
  SHA1_CTX *ctxt;
  unsigned char *out;
{
  SHA1Final (out, ctxt);
}

hash_desc SHAdesc =
{
  HASH_ID_SHA,
  "SHA",
  20,
  sha_new,
  sha_init,
  sha_update,
  sha_final,
  sha_delete
};

