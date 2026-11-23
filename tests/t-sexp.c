/* t-sexp.c  -  S-expression regression tests
 * Copyright (C) 2001, 2002, 2003, 2005 Free Software Foundation, Inc.
 * Copyright (C) 2014 g10 Code GmbH
 *
 * This file is part of Libgcrypt.
 *
 * Libgcrypt is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * Libgcrypt is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <assert.h>
#include "../src/gcrypt-int.h"

#define PGM "t-sexp"
#include "t-common.h"


/* Convert STRING consisting of hex characters into its binary
   representation and return it as an allocated buffer. The valid
   length of the buffer is returned at R_LENGTH.  The string is
   delimited by end of string.  The function returns NULL on
   error.  */
static void *
hex2buffer (const char *string, size_t *r_length)
{
  const char *s;
  unsigned char *buffer;
  size_t length;

  buffer = xmalloc (strlen(string)/2+1);
  length = 0;
  for (s=string; *s; s +=2 )
    {
      if (!hexdigitp (s) || !hexdigitp (s+1))
        return NULL;           /* Invalid hex digits. */
      ((unsigned char*)buffer)[length++] = xtoi_2 (s);
    }
  *r_length = length;
  return buffer;
}


static gcry_mpi_t
hex2mpi (const char *string)
{
  gpg_error_t err;
  gcry_mpi_t val;

  err = gcry_mpi_scan (&val, GCRYMPI_FMT_HEX, string, 0, NULL);
  if (err)
    die ("hex2mpi '%s' failed: %s\n", string, gpg_strerror (err));
  return val;
}

static gcry_mpi_t
hex2mpiopa (const char *string)
{
  char *buffer;
  size_t buflen;
  gcry_mpi_t val;

  buffer = hex2buffer (string, &buflen);
  if (!buffer)
    die ("hex2mpiopa '%s' failed: parser error\n", string);
  val = gcry_mpi_set_opaque (NULL, buffer, buflen*8);
  if (!buffer)
    die ("hex2mpiopa '%s' failed: set_opaque error\n", string);
  return val;
}


/* Compare A to B, where B is given as a hex string.  */
static int
cmp_mpihex (gcry_mpi_t a, const char *b)
{
  gcry_mpi_t bval;
  int res;

  if (gcry_mpi_get_flag (a, GCRYMPI_FLAG_OPAQUE))
    bval = hex2mpiopa (b);
  else
    bval = hex2mpi (b);
  res = gcry_mpi_cmp (a, bval);
  gcry_mpi_release (bval);
  return res;
}

/* Compare A to B, where A is a buffer and B a hex string.  */
static int
cmp_bufhex (const void *a, size_t alen, const char *b)
{
  void *bbuf;
  size_t blen;
  int res;

  if (!a && !b)
    return 0;
  if (a && !b)
    return 1;
  if (!a && b)
    return -1;

  bbuf = hex2buffer (b, &blen);
  if (!bbuf)
    die ("cmp_bufhex: error converting hex string\n");
  if (alen != blen)
    return alen < blen? -1 : 1;
  res = memcmp (a, bbuf, alen);
  xfree (bbuf);
  return res;
}



/* fixme: we need better tests */
static void
basic (void)
{
  int pass;
  gcry_sexp_t sexp;
  int idx;
  char *secure_buffer;
  size_t secure_buffer_len;
  const char *string;
  static struct {
    const char *token;
    const char *parm;
  } values[] = {
    { "public-key", NULL },
    { "dsa", NULL },
    { "dsa", "p" },
    { "dsa", "y" },
    { "dsa", "q" },
    { "dsa", "g" },
    { NULL }
  };

  info ("doing some pretty pointless tests\n");

  secure_buffer_len = 99;
  secure_buffer = gcry_xmalloc_secure (secure_buffer_len);
  memset (secure_buffer, 'G', secure_buffer_len);

  for (pass=0;;pass++)
    {
      gcry_mpi_t m;

      switch (pass)
        {
        case 0:
          string = ("(public-key (dsa (p #41424344#) (y this_is_y) "
                    "(q #61626364656667#) (g %m)))");

          m = gcry_mpi_set_ui (NULL, 42);
          if ( gcry_sexp_build (&sexp, NULL, string, m ) )
            {
              gcry_mpi_release (m);
              fail (" scanning `%s' failed\n", string);
              return;
            }
          gcry_mpi_release (m);
          break;

        case 1:
          string = ("(public-key (dsa (p #41424344#) (y this_is_y) "
                    "(q %b) (g %m)))");

          m = gcry_mpi_set_ui (NULL, 42);
          if ( gcry_sexp_build (&sexp, NULL, string,
                                15, "foo\0\x01\0x02789012345", m) )
            {
              gcry_mpi_release (m);
              fail (" scanning `%s' failed\n", string);
              return;
            }
          gcry_mpi_release (m);
          break;

        case 2:
          string = ("(public-key (dsa (p #41424344#) (y silly_y_value) "
                    "(q %b) (g %m)))");

          m = gcry_mpi_set_ui (NULL, 17);
          if ( gcry_sexp_build (&sexp, NULL, string,
                                secure_buffer_len, secure_buffer, m) )
            {
              gcry_mpi_release (m);
              fail (" scanning `%s' failed\n", string);
              return;
            }
          gcry_mpi_release (m);
          if (!gcry_is_secure (sexp))
            fail ("gcry_sexp_build did not switch to secure memory\n");
          break;

        case 3:
          {
            gcry_sexp_t help_sexp;

            if (gcry_sexp_new (&help_sexp,
                               "(foobar-parms (xp #1234#)(xq #03#))", 0, 1))
              {
                fail (" scanning fixed string failed\n");
                return;
              }

            string = ("(public-key (dsa (p #41424344#) (parm %S) "
                      "(y dummy)(q %b) (g %m)))");
            m = gcry_mpi_set_ui (NULL, 17);
            if ( gcry_sexp_build (&sexp, NULL, string, help_sexp,
                                  secure_buffer_len, secure_buffer, m) )
              {
                gcry_mpi_release (m);
                fail (" scanning `%s' failed\n", string);
                return;
              }
            gcry_mpi_release (m);
            gcry_sexp_release (help_sexp);
          }
          break;


        default:
          return; /* Ready. */
        }


      /* now find something */
      for (idx=0; values[idx].token; idx++)
        {
          const char *token = values[idx].token;
          const char *parm = values[idx].parm;
          gcry_sexp_t s1, s2;
          gcry_mpi_t a;
          const char *p;
          size_t n;

          s1 = gcry_sexp_find_token (sexp, token, strlen(token) );
          if (!s1)
            {
              fail ("didn't found `%s'\n", token);
              continue;
            }

          p = gcry_sexp_nth_data (s1, 0, &n);
          if (!p)
            {
              gcry_sexp_release (s1);
              fail ("no car for `%s'\n", token);
              continue;
            }
          /* info ("car=`%.*s'\n", (int)n, p); */

          s2 = gcry_sexp_cdr (s1);
          if (!s2)
            {
              gcry_sexp_release (s1);
              fail ("no cdr for `%s'\n", token);
              continue;
            }

          p = gcry_sexp_nth_data (s2, 0, &n);
          gcry_sexp_release (s2);
          if (p)
            {
              gcry_sexp_release (s1);
              fail ("data at car of `%s'\n", token);
              continue;
            }

          if (parm)
            {
              s2 = gcry_sexp_find_token (s1, parm, strlen (parm));
              gcry_sexp_release (s1);
              if (!s2)
                {
                  fail ("didn't found `%s'\n", parm);
                  continue;
                }
              p = gcry_sexp_nth_data (s2, 0, &n);
              if (!p)
                {
                  gcry_sexp_release (s2);
                  fail("no car for `%s'\n", parm );
                  continue;
                }
              /* info ("car=`%.*s'\n", (int)n, p); */
              p = gcry_sexp_nth_data (s2, 1, &n);
              if (!p)
                {
                  gcry_sexp_release (s2);
                  fail("no cdr for `%s'\n", parm );
                  continue;
                }
              /* info ("cdr=`%.*s'\n", (int)n, p); */

              a = gcry_sexp_nth_mpi (s2, 0, GCRYMPI_FMT_USG);
              gcry_sexp_release (s2);
              if (!a)
                {
                  fail("failed to cdr the mpi for `%s'\n", parm);
                  continue;
                }
              gcry_mpi_release (a);
            }
          else
            gcry_sexp_release (s1);
        }

      gcry_sexp_release (sexp);
      sexp = NULL;
    }
  gcry_free (secure_buffer);
}


static void
canon_len (void)
{
  static struct {
    size_t textlen; /* length of the buffer */
    size_t expected;/* expected length or 0 on error and then ... */
    size_t erroff;  /* ... and at this offset */
    gcry_error_t errcode;    /* ... with this error code */
    const char *text;
  } values[] = {
    { 14, 13, 0, GPG_ERR_NO_ERROR, "(9:abcdefghi) " },
    { 16, 15, 0, GPG_ERR_NO_ERROR, "(10:abcdefghix)" },
    { 14,  0,14, GPG_ERR_SEXP_STRING_TOO_LONG, "(10:abcdefghi)" },
    { 15,  0, 1, GPG_ERR_SEXP_ZERO_PREFIX, "(010:abcdefghi)" },
    {  2,  0, 0, GPG_ERR_SEXP_NOT_CANONICAL, "1:"},
    {  4,  0, 4, GPG_ERR_SEXP_STRING_TOO_LONG, "(1:)"},
    {  5,  5, 0, GPG_ERR_NO_ERROR, "(1:x)"},
    {  2,  2, 0, GPG_ERR_NO_ERROR, "()"},
    {  4,  2, 0, GPG_ERR_NO_ERROR, "()()"},
    {  4,  4, 0, GPG_ERR_NO_ERROR, "(())"},
    {  3,  0, 3, GPG_ERR_SEXP_STRING_TOO_LONG, "(()"},
    {  3,  0, 1, GPG_ERR_SEXP_BAD_CHARACTER, "( )"},
    {  9,  9, 0, GPG_ERR_NO_ERROR, "(3:abc())"},
    { 10,  0, 6, GPG_ERR_SEXP_BAD_CHARACTER, "(3:abc ())"},
    /* fixme: we need much more cases */
    { 0 },
  };
  int idx;
  gcry_error_t errcode;
  size_t n, erroff;

  info ("checking canoncial length test function\n");
  for (idx=0; values[idx].text; idx++)
    {
      n = gcry_sexp_canon_len ((const unsigned char*)values[idx].text,
                               values[idx].textlen,
                               &erroff, &errcode);

      if (n && n == values[idx].expected)
        ; /* success */
      else if (!n && !values[idx].expected)
        { /* we expected an error - check that this is the right one */
          if (values[idx].erroff != erroff)
            fail ("canonical length test %d - wrong error offset %u\n",
                  idx, (unsigned int)erroff);
          if (gcry_err_code (errcode) != values[idx].errcode)
            fail ("canonical length test %d - wrong error code %d\n",
                  idx, errcode);
        }
      else
        fail ("canonical length test %d failed - n=%u, off=%u, err=%d\n",
              idx, (unsigned int)n, (unsigned int)erroff, errcode);
    }
}


/* Compare SE to the canonical formatted expression in
 * (CANON,CANONLEN).  This is done by a converting SE to canonical
 * format and doing a byte compare.  Returns 0 if they match.  */
static int
compare_to_canon (gcry_sexp_t se, const unsigned char *canon, size_t canonlen)
{
  size_t n, n1;
  char *p1;

  n1 = gcry_sexp_sprint (se, GCRYSEXP_FMT_CANON, NULL, 0);
  if (!n1)
    {
      fail ("get required length in compare_to_canon failed\n");
      return -1;
    }
  p1 = gcry_xmalloc (n1);
  n = gcry_sexp_sprint (se, GCRYSEXP_FMT_CANON, p1, n1);
  if (n1 != n+1)
    {
      fail ("length mismatch in compare_to_canon detected\n");
      xfree (p1);
      return -1;
    }
  if (n1 != canonlen || memcmp (p1, canon, canonlen))
    {
      xfree (p1);
      return -1;
    }
  xfree (p1);
  return 0;
}


static void
back_and_forth_one (int testno, const char *buffer, size_t length)
{
  gcry_error_t rc;
  gcry_sexp_t se, se1;
  unsigned char *canon;
  size_t canonlen;  /* Including the hidden nul suffix.  */
  size_t n, n1;
  char *p1;

  rc = gcry_sexp_new (&se, buffer, length, 1);
  if (rc)
    {
      fail ("baf %d: gcry_sexp_new failed: %s\n", testno, gpg_strerror (rc));
      return;
    }
  n1 = gcry_sexp_sprint (se, GCRYSEXP_FMT_CANON, NULL, 0);
  if (!n1)
    {
      fail ("baf %d: get required length for canon failed\n", testno);
      return;
    }
  p1 = gcry_xmalloc (n1);
  n = gcry_sexp_sprint (se, GCRYSEXP_FMT_CANON, p1, n1);
  if (n1 != n+1) /* sprints adds an extra 0 but does not return it. */
    {
      fail ("baf %d: length mismatch for canon\n", testno);
      return;
    }
  canonlen = n1;
  canon = gcry_malloc (canonlen);
  memcpy (canon, p1, canonlen);
  rc = gcry_sexp_create (&se1, p1, n, 0, gcry_free);
  if (rc)
    {
      fail ("baf %d: gcry_sexp_create failed: %s\n",
            testno, gpg_strerror (rc));
      return;
    }
  gcry_sexp_release (se1);

  /* Again but with memory checking. */
  p1 = gcry_xmalloc (n1+2);
  *p1 = '\x55';
  p1[n1+1] = '\xaa';
  n = gcry_sexp_sprint (se, GCRYSEXP_FMT_CANON, p1+1, n1);
  if (n1 != n+1) /* sprints adds an extra 0 but does not return it */
    {
      fail ("baf %d: length mismatch for canon\n", testno);
      return;
    }
  if (*p1 != '\x55' || p1[n1+1] != '\xaa')
    fail ("baf %d: memory corrupted (1)\n", testno);
  rc = gcry_sexp_create (&se1, p1+1, n, 0, NULL);
  if (rc)
    {
      fail ("baf %d: gcry_sexp_create failed: %s\n",
            testno, gpg_strerror (rc));
      return;
    }
  if (*p1 != '\x55' || p1[n1+1] != '\xaa')
    fail ("baf %d: memory corrupted (2)\n", testno);
  gcry_sexp_release (se1);
  if (*p1 != '\x55' || p1[n1+1] != '\xaa')
    fail ("baf %d: memory corrupted (3)\n", testno);
  gcry_free (p1);

  /* Check converting to advanced format.  */
  n1 = gcry_sexp_sprint (se, GCRYSEXP_FMT_ADVANCED, NULL, 0);
  if (!n1)
    {
      fail ("baf %d: get required length for advanced failed\n", testno);
      return;
    }
  p1 = gcry_xmalloc (n1);
  n = gcry_sexp_sprint (se, GCRYSEXP_FMT_ADVANCED, p1, n1);
  if (n1 != n+1) /* sprints adds an extra 0 but does not return it */
    {
      fail ("baf %d: length mismatch for advanced\n", testno);
      return;
    }
  rc = gcry_sexp_create (&se1, p1, n, 0, gcry_free);
  if (rc)
    {
      fail ("baf %d: gcry_sexp_create failed: %s\n",
            testno, gpg_strerror (rc));
      return;
    }
  if (compare_to_canon (se1, canon, canonlen))
    {
      fail ("baf %d: converting to advanced failed: %s\n",
            testno, gpg_strerror (rc));
      return;
    }
  gcry_sexp_release (se1);


  /* FIXME: we need a lot more tests */

  gcry_sexp_release (se);
  xfree (canon);
}



static void
back_and_forth (void)
{
  static struct { const char *buf; int len; } tests[] = {
    { "(7:g34:fgh1::2:())", 0 },
    { "(7:g34:fgh1::2:())", 18 },
    {
"(protected-private-key \n"
" (rsa \n"
"  (n #00BE8A536204687149A48FF9F1715FF3530AD9A836D62102BF4065E5CF5953236DB94F1DF2FF4D525CD4CE7966DDC3C839968E8BAC2948934DF047CC65287CD79F6C23C93E55D7F9231E3942BD496DE383469977635A51ADF4AF747DB958CA02E9940DFC1DC0FC7FC755E7EB6618FEE6DA54B8A06E0CBF9D9257443F9992261435#)\n"
"  (e #010001#)\n"
"  (protected openpgp-s2k3-sha1-aes-cbc \n"
"   (\n"
"    (sha1 #C2A5673BD3882405# \"96\")\n"
"    #8D08AAF6A9209ED69D71EB7E64D78715#)\n"
"   #F7B0B535F8F8E22F4F3DA031224070303F82F9207D42952F1ACF21A4AB1C50304EBB25527992C7B265A9E9FF702826FB88759BDD55E4759E9FCA6C879538C9D043A9C60A326CB6681090BAA731289BD880A7D5774D9999F026E5E7963BFC8C0BDC9F061393CB734B4F259725C0A0A0B15BA39C39146EF6A1B3DC4DF30A22EBE09FD05AE6CB0C8C6532951A925F354F4E26A51964F5BBA50081690C421C8385C4074E9BAB9297D081B857756607EAE652415275A741C89E815558A50AC638EDC5F5030210B4395E3E1A40FF38DCCCB333A19EA88EFE7E4D51B54128C6DF27395646836679AC21B1B25C1DA6F0A7CE9F9BE078EFC7934FA9AE202CBB0AA06C20DFAF9A66FAB7E9073FBE96B9A7F25C3BA45EC3EECA65796AEE313BA148DE5314F30345B452B50B17C4D841A7F27397126E8C10BD0CE3B50A82C0425AAEE7798031671407B681F52916256F78CAF92A477AC27BCBE26DAFD1BCE386A853E2A036F8314BB2E8E5BB1F196434232EFB0288331C2AB16DBC5457CC295EB966CAC5CE73D5DA5D566E469F0EFA82F9A12B8693E0#)\n"
"  )\n"
" )\n", 0 },
    { "((sha1 #8B98CBF4A9823CA7# \"2097\") #3B6FC9#)", 0 },
    { "((4:sha18:\x8B\x98\xCB\xF4\xA9\x82\x3C\xA7""4:2097)3:\x3B\x6F\xC9)", 0},
    { "((4:sha18:\x8B\x98\xCB\x22\xA9\x82\x3C\xA7""4:2097)3:\x3B\x6F\xC9)", 0},
    { "((sha1 #64652267686970C9# \"2097\") #3B6FC9#)", 0 },
    { "((4:sha18:\x64\x65\x22\x67\x68\xc3\xa4\x71""4:2097)3:\x3B\x6F\xC9)", 0},
    { "((sha1 \"defghäq\" \"2097\") #3B6FC9#)", 0 },
    { "((sha1 \"de\\\"ghäq\" \"2097\") #3B6FC9#)", 0 },
    { NULL, 0 }
  };
  int idx;

  for (idx=0; tests[idx].buf; idx++)
    back_and_forth_one (idx, tests[idx].buf, tests[idx].len);
}


static void
check_sscan (void)
{
  static struct {
    const char *text;
    gcry_error_t expected_err;
  } values[] = {
    /* Bug reported by Olivier L'Heureux 2003-10-07 */
    { "(7:sig-val(3:dsa"
      "(1:r20:\x7e\xff\xd5\xba\xc9\xc9\xa4\x9b\xd4\x26\x8b\x64"
      "\x06\x7a\xcf\x42\x7b\x6c\x51\xfb)"
      "(1:s21:\x01\x8c\x6c\x6f\x37\x1a\x8d\xfd\x5a\xb3\x2a\x3d"
      "\xc5\xae\x23\xed\x32\x62\x30\x62\x3e)))",
      GPG_ERR_NO_ERROR },
    { "(7:sig-val(3:dsa"
      "(1:r20:\x7e\xff\xd5\xba\xc9\xc9\xa4\x9b\xd4\x26\x8b\x64"
      "\x06\x7a\xcf\x42\x7b\x6c\x51\xfb)"
      "(1:s21:\x01\x8c\x6c\x6f\x37\x1a\x8d\xfd\x5a\xb3\x2a\x3d"
      "\xc5\xae\x23\xed\x32\x62\x30\x62\x3e))",
      GPG_ERR_SEXP_UNMATCHED_PAREN },
    { "(7:sig-val(3:dsa"
      "(1:r20:\x7e\xff\xd5\xba\xc9\xc9\xa4\x9b\xd4\x26\x8b\x64"
      "\x06\x7a\xcf\x42\x7b\x6c\x51\xfb)"
      "(1:s21:\x01\x8c\x6c\x6f\x37\x1a\x8d\xfd\x5a\xb3\x2a\x3d"
      "\xc5\xae\x23\xed\x32\x62\x30\x62\x3e))))",
      GPG_ERR_SEXP_UNMATCHED_PAREN },
    { NULL, 0 }
  };
  int idx;
  gcry_error_t err;
  gcry_sexp_t s;

  info ("checking gcry_sexp_sscan\n");
  for (idx=0; values[idx].text; idx++)
    {
      err = gcry_sexp_sscan (&s, NULL,
                             values[idx].text,
                             strlen (values[idx].text));
      if (gpg_err_code (err) != values[idx].expected_err)
        fail ("gcry_sexp_sscan test %d failed: %s\n", idx, gpg_strerror (err));
      gcry_sexp_release (s);
    }
}


static void
check_extract_param (void)
{
  /* This sample data is a real key but with some parameters of the
     public key modified.  u,i,I are used for direct extraction tests. */
  static char sample1[] =
    "(key-data"
    " (public-key"
    "  (ecc"
    "   (curve Ed25519)"
    "   (p #6FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFED#)"
    "   (a #EF#)"
    "   (b #C2036CEE2B6FFE738CC740797779E89800700A4D4141D8AB75EB4DCA135978B6#)"
    "   (g #14"
    "       216936D3CD6E53FEC0A4E231FDD6DC5C692CC7609525A7B2C9562D608F25D51A"
    "       6666666666666666666666666666666666666666666666666666666666666658#)"
    "   (n #0000000000000000000000000000000014DEF9DEA2F79CD65812631A5CF5D3ED#)"
    "   (q #20B37806015CA06B3AEB9423EE84A41D7F31AA65F4148553755206D679F8BF62#)"
    "))"
    " (private-key"
    "  (u +65537)"
    "  (i +65537)"
    "  (I -65535)"
    "  (i0 1:0)"
    "  (flaglist foo     bar (sublist x) test 2:42)"
    "  (noflags)"
    "  (ecc"
    "   (curve Ed25519)"
    "   (p #7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFED#)"
    "   (a #FF#)"
    "   (b #D2036CEE2B6FFE738CC740797779E89800700A4D4141D8AB75EB4DCA135978B6#)"
    "   (g #04"
    "       216936D3CD6E53FEC0A4E231FDD6DC5C692CC7609525A7B2C9562D608F25D51A"
    "       6666666666666666666666666666666666666666666666666666666666666658#)"
    "   (n #1000000000000000000000000000000014DEF9DEA2F79CD65812631A5CF5D3ED#)"
    "   (q #30B37806015CA06B3AEB9423EE84A41D7F31AA65F4148553755206D679F8BF62#)"
    "   (d #56BEA284A22F443A7AEA8CEFA24DA5055CDF1D490C94D8C568FE0802C9169276#)"
    "   (comment |QWxsIHlvdXIgYmFzZTY0IGFyZSBiZWxvbmcgdG8gdXM=|)"
    ")))";

  static char sample1_p[] =
    "7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFED";
  static char sample1_px[] =
    "6FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFED";
  static char sample1_a[] = "FF";
  static char sample1_ax[] = "EF";
  static char sample1_b[] =
    "D2036CEE2B6FFE738CC740797779E89800700A4D4141D8AB75EB4DCA135978B6";
  static char sample1_bx[] =
    "C2036CEE2B6FFE738CC740797779E89800700A4D4141D8AB75EB4DCA135978B6";
  static char sample1_g[] =
    "04"
    "216936D3CD6E53FEC0A4E231FDD6DC5C692CC7609525A7B2C9562D608F25D51A"
    "6666666666666666666666666666666666666666666666666666666666666658";
  static char sample1_gx[] =
    "14"
    "216936D3CD6E53FEC0A4E231FDD6DC5C692CC7609525A7B2C9562D608F25D51A"
    "6666666666666666666666666666666666666666666666666666666666666658";
  static char sample1_n[] =
    "1000000000000000000000000000000014DEF9DEA2F79CD65812631A5CF5D3ED";
  static char sample1_nx[] =
    "0000000000000000000000000000000014DEF9DEA2F79CD65812631A5CF5D3ED";
  static char sample1_q[] =
    "30B37806015CA06B3AEB9423EE84A41D7F31AA65F4148553755206D679F8BF62";
  static char sample1_qx[] =
    "20B37806015CA06B3AEB9423EE84A41D7F31AA65F4148553755206D679F8BF62";
  static char sample1_d[] =
    "56BEA284A22F443A7AEA8CEFA24DA5055CDF1D490C94D8C568FE0802C9169276";
  static char sample1_comment[] = "All your base64 are belong to us";

  static struct {
    const char *sexp_str;
    const char *path;
    const char *list;
    int nparam;
    gpg_err_code_t expected_err;
    const char *exp_p;
    const char *exp_a;
    const char *exp_b;
    const char *exp_g;
    const char *exp_n;
    const char *exp_q;
    const char *exp_d;
  } tests[] = {
    {
      sample1,
      NULL,
      "pabgnqd", 6,
      GPG_ERR_MISSING_VALUE,
    },
    {
      sample1,
      NULL,
      "pabgnq", 7,
      GPG_ERR_INV_ARG
    },
    {
      sample1,
      NULL,
      "pab'gnq", 7,
      GPG_ERR_SYNTAX
    },
    {
      sample1,
      NULL,
      "pab''gnq", 7,
      GPG_ERR_SYNTAX
    },
    {
      sample1,
      NULL,
      "pabgnqd", 7,
      0,
      sample1_px, sample1_ax, sample1_bx, sample1_gx, sample1_nx,
      sample1_qx, sample1_d
    },
    {
      sample1,
      NULL,
      "  pab\tg nq\nd  ", 7,
      0,
      sample1_px, sample1_ax, sample1_bx, sample1_gx, sample1_nx,
      sample1_qx, sample1_d
    },
    {
      sample1,
      NULL,
      "abg", 3,
      0,
      sample1_ax, sample1_bx, sample1_gx
    },
    {
      sample1,
      NULL,
      "ab'g'", 3,
      0,
      sample1_ax, sample1_bx, sample1_gx
    },
    {
      sample1,
      NULL,
      "x?abg", 4,
      0,
      NULL, sample1_ax, sample1_bx, sample1_gx
    },
    {
      sample1,
      NULL,
      "p?abg", 4,
      GPG_ERR_USER_1,
      NULL, sample1_ax, sample1_bx, sample1_gx
    },
    {
      sample1,
      NULL,
      "pax?gnqd", 7,
      0,
      sample1_px, sample1_ax, NULL, sample1_gx, sample1_nx,
      sample1_qx, sample1_d
    },
    {
      sample1,
      "public-key",
      "pabgnqd", 7,
      GPG_ERR_NO_OBJ,  /* d is not in public key.  */
      sample1_px, sample1_ax, sample1_bx, sample1_gx, sample1_nx,
      sample1_qx, sample1_d
    },
    {
      sample1,
      "private-key",
      "pabgnqd", 7,
      0,
      sample1_p, sample1_a, sample1_b, sample1_g, sample1_n,
      sample1_q, sample1_d
    },
    {
      sample1,
      "public-key!ecc",
      "pabgnq", 6,
      0,
      sample1_px, sample1_ax, sample1_bx, sample1_gx, sample1_nx,
      sample1_qx
    },
    {
      sample1,
      "public-key!ecc!foo",
      "pabgnq", 6,
      GPG_ERR_NOT_FOUND
    },
    {
      sample1,
      "public-key!!ecc",
      "pabgnq", 6,
      GPG_ERR_NOT_FOUND
    },
    {
      sample1,
      "private-key",
      "pa/bgnqd", 7,
      0,
      sample1_p, sample1_a, sample1_b, sample1_g, sample1_n,
      sample1_q, sample1_d
    },
    {
      sample1,
      "private-key",
      "p-a+bgnqd", 7,
      0,
      sample1_p, "-01", sample1_b, sample1_g, sample1_n,
      sample1_q, sample1_d
    },
    {NULL}
  };
  int idx, i;
  const char *paramstr;
  int paramidx;
  gpg_error_t err;
  gcry_sexp_t sxp, sxp1;
  gcry_mpi_t mpis[7];
  gcry_buffer_t ioarray[7];
  char iobuffer[200];
  char *string1, *string2;
  int aint0, aint1, aint2;
  unsigned int auint;
  long along1, along2;
  unsigned long aulong;
  size_t asize;

  info ("checking gcry_sexp_extract_param\n");
  for (idx=0; tests[idx].sexp_str; idx++)
    {
      err = gcry_sexp_new (&sxp, tests[idx].sexp_str, 0, 1);
      if (err)
        die ("converting string to sexp failed: %s", gpg_strerror (err));

      memset (mpis, 0, sizeof mpis);
      switch (tests[idx].nparam)
        {
        case 0:
          err = gcry_sexp_extract_param (sxp, tests[idx].path, tests[idx].list,
                                         NULL);
          break;
        case 1:
          err = gcry_sexp_extract_param (sxp, tests[idx].path, tests[idx].list,
                                         mpis+0, NULL);
          break;
        case 2:
          err = gcry_sexp_extract_param (sxp, tests[idx].path, tests[idx].list,
                                         mpis+0, mpis+1, NULL);
          break;
        case 3:
          err = gcry_sexp_extract_param (sxp, tests[idx].path, tests[idx].list,
                                         mpis+0, mpis+1, mpis+2, NULL);
          break;
        case 4:
          err = gcry_sexp_extract_param (sxp, tests[idx].path, tests[idx].list,
                                         mpis+0, mpis+1, mpis+2, mpis+3, NULL);
          break;
        case 5:
          err = gcry_sexp_extract_param (sxp, tests[idx].path, tests[idx].list,
                                         mpis+0, mpis+1, mpis+2, mpis+3, mpis+4,
                                         NULL);
          break;
        case 6:
          err = gcry_sexp_extract_param (sxp, tests[idx].path, tests[idx].list,
                                         mpis+0, mpis+1, mpis+2, mpis+3, mpis+4,
                                         mpis+5, NULL);
          break;
        case 7:
          err = gcry_sexp_extract_param (sxp, tests[idx].path, tests[idx].list,
                                         mpis+0, mpis+1, mpis+2, mpis+3, mpis+4,
                                         mpis+5, mpis+6, NULL);
          break;
        default:
          die ("test %d: internal error", idx);
        }

      if (tests[idx].expected_err
          && tests[idx].expected_err != GPG_ERR_USER_1)
        {
          if (tests[idx].expected_err != gpg_err_code (err))
            fail ("gcry_sexp_extract_param test %d failed: "
                  "expected error '%s' - got '%s'", idx,
                  gpg_strerror (tests[idx].expected_err),gpg_strerror (err));

        }
      else if (err)
        {
          fail ("gcry_sexp_extract_param test %d failed: %s",
                idx, gpg_strerror (err));
        }
      else /* No error - check the extracted values.  */
        {
          for (paramidx=0; paramidx < DIM (mpis); paramidx++)
            {
              switch (paramidx)
                {
                case 0: paramstr = tests[idx].exp_p; break;
                case 1: paramstr = tests[idx].exp_a; break;
                case 2: paramstr = tests[idx].exp_b; break;
                case 3: paramstr = tests[idx].exp_g; break;
                case 4: paramstr = tests[idx].exp_n; break;
                case 5: paramstr = tests[idx].exp_q; break;
                case 6: paramstr = tests[idx].exp_d; break;
                default:
                  die ("test %d: internal error: bad param %d",
                       idx, paramidx);
                }

              if (tests[idx].expected_err == GPG_ERR_USER_1
                  && mpis[paramidx] && !paramstr && paramidx == 0)
                ; /* Okay  Special case error for param 0.  */
              else if (!mpis[paramidx] && !paramstr)
                ; /* Okay.  */
              else if (!mpis[paramidx] && paramstr)
                fail ("test %d: value for param %d expected but not returned",
                      idx, paramidx);
              else if (mpis[paramidx] && !paramstr)
                fail ("test %d: value for param %d not expected",
                      idx, paramidx);
              else if (cmp_mpihex (mpis[paramidx], paramstr))
                {
                  fail ("test %d: param %d mismatch", idx, paramidx);
                  gcry_log_debug    ("expected: %s\n", paramstr);
                  gcry_log_debugmpi ("     got", mpis[paramidx]);
                }
              else if (tests[idx].expected_err && paramidx == 0)
                fail ("test %d: param %d: expected error '%s' - got 'Success'",
                      idx, paramidx, gpg_strerror (tests[idx].expected_err));
            }

        }

      for (i=0; i < DIM (mpis); i++)
        gcry_mpi_release (mpis[i]);
      gcry_sexp_release (sxp);
    }

  info ("checking gcry_sexp_extract_param/desc\n");

  memset (ioarray, 0, sizeof ioarray);

  err = gcry_sexp_new (&sxp, sample1, 0, 1);
  if (err)
    die ("converting string to sexp failed: %s", gpg_strerror (err));

  ioarray[1].size = sizeof iobuffer;
  ioarray[1].data = iobuffer;
  ioarray[1].off  = 0;
  ioarray[2].size = sizeof iobuffer;
  ioarray[2].data = iobuffer;
  ioarray[2].off  = 50;
  assert (ioarray[2].off < sizeof iobuffer);
  err = gcry_sexp_extract_param (sxp, "key-data!private-key", "&pab",
                                 ioarray+0, ioarray+1, ioarray+2, NULL);
  if (err)
    fail ("gcry_sexp_extract_param with desc failed: %s", gpg_strerror (err));
  else
    {
      if (!ioarray[0].data)
        fail ("gcry_sexp_extract_param/desc failed: no P");
      else if (ioarray[0].size != 32)
        fail ("gcry_sexp_extract_param/desc failed: P has wrong size");
      else if (ioarray[0].len != 32)
        fail ("gcry_sexp_extract_param/desc failed: P has wrong length");
      else if (ioarray[0].off)
        fail ("gcry_sexp_extract_param/desc failed: P has OFF set");
      else if (cmp_bufhex (ioarray[0].data, ioarray[0].len, sample1_p))
        {
          fail ("gcry_sexp_extract_param/desc failed: P mismatch");
          gcry_log_debug    ("expected: %s\n", sample1_p);
          gcry_log_debughex ("     got", ioarray[0].data, ioarray[0].len);
        }

      if (!ioarray[1].data)
        fail ("gcry_sexp_extract_param/desc failed: A buffer lost");
      else if (ioarray[1].size != sizeof iobuffer)
        fail ("gcry_sexp_extract_param/desc failed: A size changed");
      else if (ioarray[1].off != 0)
        fail ("gcry_sexp_extract_param/desc failed: A off changed");
      else if (ioarray[1].len != 1)
        fail ("gcry_sexp_extract_param/desc failed: A has wrong length");
      else if (cmp_bufhex ((char *)ioarray[1].data + ioarray[1].off,
                           ioarray[1].len, sample1_a))
        {
          fail ("gcry_sexp_extract_param/desc failed: A mismatch");
          gcry_log_debug    ("expected: %s\n", sample1_a);
          gcry_log_debughex ("     got",
                             (char *)ioarray[1].data + ioarray[1].off,
                             ioarray[1].len);
        }

      if (!ioarray[2].data)
        fail ("gcry_sexp_extract_param/desc failed: B buffer lost");
      else if (ioarray[2].size != sizeof iobuffer)
        fail ("gcry_sexp_extract_param/desc failed: B size changed");
      else if (ioarray[2].off != 50)
        fail ("gcry_sexp_extract_param/desc failed: B off changed");
      else if (ioarray[2].len != 32)
        fail ("gcry_sexp_extract_param/desc failed: B has wrong length");
      else if (cmp_bufhex ((char *)ioarray[2].data + ioarray[2].off,
                           ioarray[2].len, sample1_b))
        {
          fail ("gcry_sexp_extract_param/desc failed: B mismatch");
          gcry_log_debug    ("expected: %s\n", sample1_b);
          gcry_log_debughex ("     got",
                             (char *)ioarray[2].data + ioarray[2].off,
                             ioarray[2].len);
        }

      xfree (ioarray[0].data);
    }

  gcry_sexp_release (sxp);

  info ("checking gcry_sexp_extract_param long name\n");

  memset (ioarray, 0, sizeof ioarray);
  memset (mpis, 0, sizeof mpis);

  err = gcry_sexp_new (&sxp, sample1, 0, 1);
  if (err)
    die ("converting string to sexp failed: %s", gpg_strerror (err));

  err = gcry_sexp_extract_param (sxp, "key-data!private-key",
                                 "&'curve'+p",
                                 ioarray+0, mpis+0, NULL);
  if (err)
    fail ("gcry_sexp_extract_param long name failed: %s", gpg_strerror (err));

  if (!ioarray[0].data)
    fail ("gcry_sexp_extract_param long name failed: no curve");
  else if (ioarray[0].size != 7)
    fail ("gcry_sexp_extract_param long name failed: curve has wrong size");
  else if (ioarray[0].len != 7)
    fail ("gcry_sexp_extract_param long name failed: curve has wrong length");
  else if (ioarray[0].off)
    fail ("gcry_sexp_extract_param long name failed: curve has OFF set");
  else if (strncmp (ioarray[0].data, "Ed25519", 7))
    {
      fail ("gcry_sexp_extract_param long name failed: curve mismatch");
      gcry_log_debug ("expected: %s\n", "Ed25519");
      gcry_log_debug ("     got: %.*s\n",
                      (int)ioarray[0].len, (char*)ioarray[0].data);
    }

  if (!mpis[0])
    fail ("gcry_sexp_extract_param long name failed: p not returned");
  else if (cmp_mpihex (mpis[0], sample1_p))
    {
      fail ("gcry_sexp_extract_param long name failed: p mismatch");
      gcry_log_debug    ("expected: %s\n", sample1_p);
      gcry_log_debugmpi ("     got", mpis[0]);
    }

  gcry_free (ioarray[0].data);
  gcry_mpi_release (mpis[0]);

  sxp1 = gcry_sexp_find_token (sxp, "comment", 7);
  if (!sxp1)
    fail ("gcry_sexp_nth_string faild: no SEXP for comment found");
  else
    {
      char *comment = gcry_sexp_nth_string (sxp1, 1);

      if (!comment)
        fail ("gcry_sexp_nth_string faild: no comment found");
      else
        {
          if (strcmp (comment, sample1_comment))
            fail ("gcry_sexp_sscan faild for base64");
          xfree (comment);
        }

      gcry_sexp_release (sxp1);
    }

  info ("checking gcry_sexp_extract_param new modes\n");

  memset (mpis, 0, sizeof mpis);

  gcry_sexp_release (sxp);
  err = gcry_sexp_new (&sxp, sample1, 0, 1);
  if (err)
    die ("converting string to sexp failed: %s", gpg_strerror (err));

  err = gcry_sexp_extract_param (sxp, "key-data!private-key",
                                 "%s'curve'+p%s'comment'"
                                 "%uu%di%dI%d'i0'"
                                 "%luu%ldi %ldI"
                                 "%zui",
                                 &string1, mpis+0, &string2,
                                 &auint, &aint1, &aint2, &aint0,
                                 &aulong, &along1, &along2,
                                 &asize,
                                 NULL);
  if (err)
    fail ("gcry_sexp_extract_param new modes failed: %s", gpg_strerror (err));

  if (!string1)
    fail ("gcry_sexp_extract_param new modes: no curve");
  else if (strcmp (string1, "Ed25519"))
    {
      fail ("gcry_sexp_extract_param new modes failed: curve mismatch");
      gcry_log_debug ("expected: %s\n", "Ed25519");
      gcry_log_debug ("     got: %s\n", string1);
    }

  if (!mpis[0])
    fail ("gcry_sexp_extract_param new modes failed: p not returned");
  else if (cmp_mpihex (mpis[0], sample1_p))
    {
      fail ("gcry_sexp_extract_param new modes failed: p mismatch");
      gcry_log_debug    ("expected: %s\n", sample1_p);
      gcry_log_debugmpi ("     got", mpis[0]);
    }

  if (auint != 65537)
    fail ("gcry_sexp_extract_param new modes failed: auint mismatch");
  if (aint1 != 65537)
    fail ("gcry_sexp_extract_param new modes failed: aint1 mismatch");
  if (aint2 != -65535)
    fail ("gcry_sexp_extract_param new modes failed: aint2 mismatch");
  if (aint0)
    fail ("gcry_sexp_extract_param new modes failed: aint0 mismatch");
  if (aulong != 65537)
    fail ("gcry_sexp_extract_param new modes failed: aulong mismatch");
  if (along1 != 65537)
    fail ("gcry_sexp_extract_param new modes failed: along1 mismatch");
  if (along2 != -65535)
    fail ("gcry_sexp_extract_param new modes failed: along2 mismatch");
  if (asize != 65537)
    fail ("gcry_sexp_extract_param new modes failed: asize mismatch");


  gcry_free (string1);
  gcry_free (string2);
  gcry_mpi_release (mpis[0]);


  info ("checking gcry_sexp_extract_param flag list\n");

  gcry_sexp_release (sxp);
  err = gcry_sexp_new (&sxp, sample1, 0, 1);
  if (err)
    die ("converting string to sexp failed: %s", gpg_strerror (err));

  err = gcry_sexp_extract_param (sxp, "key-data!private-key",
                                 "%#s'flaglist''noflags'",
                                 &string1, &string2,
                                 NULL);
  if (err)
    fail ("gcry_sexp_extract_param flag list failed: %s", gpg_strerror (err));

  if (!string1)
    fail ("gcry_sexp_extract_param flaglist: no flaglist");
  else if (strcmp (string1, "foo bar () test 42"))
    {
      fail ("gcry_sexp_extract_param flag list failed: wrong list");
      gcry_log_debug ("expected: %s\n", "foo bar ( ) test 42");
      gcry_log_debug ("     got: %s\n", string1);
    }

  if (!string2)
    fail ("gcry_sexp_extract_param flaglist: no second flaglist");
  else if (strcmp (string2, ""))
    {
      fail ("gcry_sexp_extract_param flag list failed: wrong list");
      gcry_log_debug ("expected: '%s'\n", "");
      gcry_log_debug ("     got: '%s'\n", string2);
    }

  gcry_free (string1);
  gcry_free (string2);


  gcry_sexp_release (sxp);
}


/* A test based on bug 1594.  */
static void
bug_1594 (void)
{
static char thing[] =
  "(signature"
  " (public-key"
  "  (rsa"
  "   (n #00A53A6B3A50BE571F805BD98ECE1FCE4CE291C3D4D3E971740E1EE6D447F526"
  "       6AC8973DDC82F0ADD234CC82E0A0A3F48B81ACC8B038DB8ACC3E78DC2ED2642F"
  "       6BA353FCA60F47C2801DEB477B37FB8B2F5508AA1C6D922780DB142DEA19B812"
  "       C4E64F1138AD3BD61C58DB2D2591BE0BF36A1AC588AA45763BCDFF581050ABA8"
  "       CA47BD9723ADD6A308AE28471EDD2B16D03C941D4F2B7E019C43AF8972880633"
  "       54E97B7E19F1677D84B69A26B184A77B719DD72C48E0EE36107046F786566A9D"
  "       13BAD724D6D78F24700FC22FC000E1B2A8C1B08ED62008395B0764CD9B55E80D"
  "       A0A2B61C698DC27EA98E68BB576ACFC2B91B4D7283E7D960948D049D6E3C4CB1"
  "       F489B460A120A4BB6C04A843FD3A67454136DE61CF68A927871EFFA9141BD372"
  "       A748593C703E0301F039A9E674C50301BFC385BABE5B154250E7D57B82DB31F1"
  "       E1AC696F870DCD8FE8DEC75608B988FCA3B484F1FD7755BF452F99597269AF02"
  "       E8AF87D0F93DB427291659183D077254C835BFB6DDFD87CD0B5E0738682FCD34"
  "       923F22551F73944E6CBE3ED6879B4414676B5DA0F30ED21DFA12BD2230C3C5D2"
  "       EA116A3EFEB4AEC21C58E63FAFA549A63190F01859445E9B80F427B80FD4C884"
  "       2AD41FE760A3E9DEDFB56CEBE8EA783838B2B392CACDDC760CCE212E388AFBC1"
  "       95DC6D0ED87E9091F82A82CE372738C8DE8ABD76ACD06AC8B80AA0597162DF59"
  "       67#)"
  "   (e #010001#))))";
  gcry_sexp_t sig, pubkey, n, n_val;

  info ("checking fix for bug 1594\n");

  if (gcry_sexp_new (&sig, thing, 0, 1))
    die ("scanning fixed string failed\n");
  pubkey = gcry_sexp_find_token (sig, "public-key", 0);
  gcry_sexp_release (sig);
  if (!pubkey)
    {
      fail ("'public-key' token not found");
      return;
    }
  n = gcry_sexp_find_token (pubkey, "n", 0);
  if (!n)
    {
      fail ("'n' token not found");
      gcry_sexp_release (pubkey);
      return;
    }
  n_val = gcry_sexp_nth (n, 1);
  /* Bug 1594 would require the following test:
   *   if (n_val)
   *     fail ("extracting 1-th of 'n' list did not fail");
   * However, we meanwhile modified the S-expression functions to
   * behave like Scheme to allow the access of any element of a list.
   */
  if (!n_val)
    fail ("extracting 1-th of 'n' list failed");
  /*gcry_log_debugsxp ("1-th", n_val); => "(#00A5...#)"  */
  gcry_sexp_release (n_val);
  n_val = gcry_sexp_nth (n, 2);
  if (n_val)
    fail ("extracting 2-th of 'n' list did not fail");
  n_val = gcry_sexp_nth (n, 0);
  if (!n_val)
    fail ("extracting 0-th of 'n' list failed");
  /*gcry_log_debugsxp ("0-th", n_val); => "(n)"  */
  if (gcry_sexp_nth (n_val, 1))
    fail ("extracting 1-th of car of 'n' list did not fail");
  gcry_sexp_release (n_val);
  gcry_sexp_release (n);
  gcry_sexp_release (pubkey);
}


/* Helper for the untrusted-input tests below: scan BUFFER/LENGTH and
 * require that it fails with WANT_CODE.  The returned sexp handle must
 * always be NULL on failure so that the caller never has to release a
 * partially built object.  When WANT_OFF is not (size_t)-1 the error
 * offset reported by the parser is checked as well.  */
static void
require_sscan_failure (const char *what, const char *buffer, size_t length,
                       gpg_err_code_t want_code, size_t want_off)
{
  gcry_sexp_t sexp = NULL;
  size_t erroff = (size_t)-2;
  gpg_error_t err;

  err = gcry_sexp_sscan (&sexp, &erroff, buffer, length);
  if (!err)
    {
      fail ("%s: parsing unexpectedly succeeded (want error %d)\n",
            what, want_code);
      gcry_sexp_release (sexp);
      return;
    }
  if (gpg_err_code (err) != want_code)
    fail ("%s: expected error %d but got %d (%s)\n", what, want_code,
          gpg_err_code (err), gpg_strerror (err));
  if (sexp)
    {
      fail ("%s: parser returned a non-NULL sexp on error\n", what);
      gcry_sexp_release (sexp);
    }
  if (want_off != (size_t)-1 && erroff != want_off)
    fail ("%s: expected error offset %u but got %u\n", what,
          (unsigned int)want_off, (unsigned int)erroff);
}


/* Build a balanced canonical expression nested DEPTH levels deep with
 * a single leaf "1:x" and return it in a newly malloced buffer.  *R_LEN
 * receives the number of valid bytes.  The shape is
 * "((...(1:x)...))" with DEPTH opening and DEPTH closing parentheses.  */
static char *
make_nested_buffer (int depth, size_t *r_len)
{
  size_t len = (size_t)depth * 2 + 3;
  char *buf = xmalloc (len + 1);
  size_t pos;

  memset (buf, '(', depth);
  pos = depth;
  memcpy (buf + pos, "1:x", 3);
  pos += 3;
  memset (buf + pos, ')', depth);
  pos += depth;
  buf[pos] = 0;
  *r_len = pos;
  return buf;
}


/* Feed the parser untrusted input whose nesting is either deeply
 * nested but balanced or structurally broken.  The parser is iterative
 * (it tracks the nesting level in an integer instead of recursing), so
 * even very deep nesting must not exhaust the stack and must only use
 * memory proportional to the supplied buffer.  Malformed nesting has to
 * be reported with a distinguishable error and without leaking the
 * partially built object.  */
static void
check_nesting (void)
{
  /* Depths at which the full node structure is walked with
   * gcry_sexp_nth.  They stay well below 32767 because that accessor
   * stores its scan level in a signed 16 bit counter.  */
  static const int depths[] = { 1, 2, 16, 256, 1024, 10000 };
  /* A depth beyond the accessor's 16 bit limit, used to prove that the
   * parser itself stays iterative and bounded; this object is only
   * inspected through gcry_sexp_sprint, never gcry_sexp_nth.  */
  enum { DEEP_PARSE_DEPTH = 50000 };
  int idx;
  char *buf;
  size_t len;
  gcry_sexp_t sexp;
  gpg_error_t err;

  info ("checking nested expressions from untrusted input\n");

  /* A legal, deeply nested expression keeps its full node structure:
   * walking DEPTH car steps must reach the single leaf and the leaf
   * must contain exactly the bytes "x".  */
  for (idx = 0; idx < DIM (depths); idx++)
    {
      int depth = depths[idx];
      int level;
      gcry_sexp_t cur, inner;
      size_t datalen;
      const char *data;

      buf = make_nested_buffer (depth, &len);
      sexp = NULL;
      err = gcry_sexp_sscan (&sexp, NULL, buf, len);
      if (err)
        {
          fail ("depth %d: legal nested expression rejected: %s\n",
                depth, gpg_strerror (err));
          xfree (buf);
          continue;
        }

      cur = sexp;
      for (level = 0; level < depth; level++)
        {
          /* gcry_sexp_nth returns a freshly allocated copy, so each
           * intermediate node has to be released after descending.  */
          inner = gcry_sexp_nth (cur, 0);
          if (cur != sexp)
            gcry_sexp_release (cur);
          if (!inner)
            {
              fail ("depth %d: node structure broken at level %d\n",
                    depth, level);
              cur = NULL;
              break;
            }
          cur = inner;
        }
      if (cur && level == depth)
        {
          data = gcry_sexp_nth_data (cur, 0, &datalen);
          if (!data || datalen != 1 || data[0] != 'x')
            fail ("depth %d: leaf node content not preserved\n", depth);
        }
      if (cur && cur != sexp)
        gcry_sexp_release (cur);
      gcry_sexp_release (sexp);
      xfree (buf);
    }

  /* Parser stack/heap boundedness: an input nested far beyond any
   * recursion limit must still parse without growing resources beyond
   * the size of the input, and round trip through the canonical writer.
   * No gcry_sexp_nth walk is done here on purpose (see above).  */
  buf = make_nested_buffer (DEEP_PARSE_DEPTH, &len);
  sexp = NULL;
  err = gcry_sexp_sscan (&sexp, NULL, buf, len);
  if (err)
    fail ("deep parse: expression nested %d levels rejected: %s\n",
          DEEP_PARSE_DEPTH, gpg_strerror (err));
  else
    {
      size_t canonlen = gcry_sexp_sprint (sexp, GCRYSEXP_FMT_CANON,
                                          NULL, 0);
      /* The canonical encoding is the input plus one trailing NUL.  */
      if (!canonlen || canonlen > len + 1)
        fail ("deep parse: output size %u not bounded by input %u\n",
              (unsigned int)canonlen, (unsigned int)len);
    }
  gcry_sexp_release (sexp);
  xfree (buf);

  /* The same deep input with one closing parenthesis removed is
   * rejected rather than parsed: structural errors stay detectable at
   * depth and no object is returned.  */
  buf = make_nested_buffer (DEEP_PARSE_DEPTH, &len);
  buf[--len] = 0;
  require_sscan_failure ("unbalanced deep expression", buf, len,
                         GPG_ERR_SEXP_UNMATCHED_PAREN, (size_t)-1);
  xfree (buf);

  /* A closing parenthesis without an opener is rejected immediately.  */
  require_sscan_failure ("stray closing parenthesis", "(1:x))", 6,
                         GPG_ERR_SEXP_UNMATCHED_PAREN, 5);

  /* Empty and half-open buffers never produce a sexp object.  */
  require_sscan_failure ("only open parenthesis", "(", 1,
                         GPG_ERR_SEXP_UNMATCHED_PAREN, (size_t)-1);
}


/* Exercise explicit length declarations ("N:data") on untrusted
 * buffers.  A declared length that runs past the end of the buffer, an
 * invalid length specification and a leading zero each have their own
 * error code, and in every failure case the parser must not allocate
 * memory based on the (attacker controlled) declared length.  */
static void
check_length_decl (void)
{
  static struct
  {
    const char *text;
    size_t length;
    gpg_err_code_t errcode;
    size_t erroff;       /* (size_t)-1 means: do not check the offset */
  } bad[] =
    {
      /* Declared 10 bytes but only 2 follow: truncated content.  */
      { "(10:ab)",          7, GPG_ERR_SEXP_STRING_TOO_LONG, 3 },
      /* Length prefix present, colon missing before the buffer ends.  */
      { "(3:",              3, GPG_ERR_SEXP_STRING_TOO_LONG, 2 },
      /* Declared payload but the buffer ends right after the colon.  */
      { "(1:",              3, GPG_ERR_SEXP_STRING_TOO_LONG, 2 },
      /* A length has to be followed by a colon.  */
      { "(3ax)",            5, GPG_ERR_SEXP_INV_LEN_SPEC,    2 },
      /* Lengths may not start with a zero.  */
      { "(01:x)",           6, GPG_ERR_SEXP_ZERO_PREFIX,     1 },
      /* A length beyond the 65535 byte DATALEN limit is invalid.  */
      { "(65536:x)",        9, GPG_ERR_INV_ARG,              6 },
      /* Huge declared length with a tiny buffer: the parser must only
       * touch the bytes actually present and never try to reserve the
       * declared amount of memory.  */
      { "(999999999:ab)",  14, GPG_ERR_INV_ARG,             10 },
    };
  static const char *good[] =
    {
      "(1:x)",
      "(3:abc)",
      "(5:a\"b\\c)",          /* quote and backslash are plain data here */
      "(2:ab(1:x))",
    };
  int idx;
  gcry_sexp_t sexp;
  gpg_error_t err;
  size_t datalen;
  const char *data;

  info ("checking length declarations on untrusted input\n");

  for (idx = 0; idx < DIM (bad); idx++)
    require_sscan_failure ("bad length declaration", bad[idx].text,
                           bad[idx].length, bad[idx].errcode,
                           bad[idx].erroff);

  /* Well formed declarations parse and preserve exactly the declared
   * number of bytes, including non-token bytes.  */
  for (idx = 0; idx < DIM (good); idx++)
    {
      sexp = NULL;
      err = gcry_sexp_sscan (&sexp, NULL, good[idx], strlen (good[idx]));
      if (err)
        {
          fail ("good declaration %d rejected: %s\n", idx,
                gpg_strerror (err));
          continue;
        }
      data = gcry_sexp_nth_data (sexp, 0, &datalen);
      if (!data)
        fail ("good declaration %d: no data node returned\n", idx);
      else if (good[idx][1] != ':'
               && datalen != (size_t)(good[idx][1] - '0'))
        fail ("good declaration %d: node length %u does not match\n",
              idx, (unsigned int)datalen);
      gcry_sexp_release (sexp);
    }

  /* The canonical length scanner has to apply the same bounded checks:
   * it scans at most LENGTH bytes and reports distinguishable codes.  */
  {
    static struct
    {
      const char *text;
      size_t length;
      gpg_err_code_t errcode;
    } canon_bad[] =
      {
        { "(10:abc)", 8, GPG_ERR_SEXP_STRING_TOO_LONG },
        { "(1:)",     4, GPG_ERR_SEXP_STRING_TOO_LONG },
        { "(01:x)",   6, GPG_ERR_SEXP_ZERO_PREFIX     },
        { "(3ax)",    5, GPG_ERR_SEXP_INV_LEN_SPEC    },
        { "(()",      3, GPG_ERR_SEXP_STRING_TOO_LONG },
        { "( )",      3, GPG_ERR_SEXP_BAD_CHARACTER   },
        { "1:x",      3, GPG_ERR_SEXP_NOT_CANONICAL   },
      };
    gpg_err_code_t ec;
    size_t eo, n;

    for (idx = 0; idx < DIM (canon_bad); idx++)
      {
        ec = 0;
        eo = 0;
        n = gcry_sexp_canon_len ((const unsigned char *)canon_bad[idx].text,
                                 canon_bad[idx].length, &eo, &ec);
        if (n || gpg_err_code (ec) != canon_bad[idx].errcode)
          fail ("canon_len case %d: got n=%u err=%d (%s), want err=%d\n",
                idx, (unsigned int)n, gpg_err_code (ec),
                gpg_strerror (ec), canon_bad[idx].errcode);
      }
  }
}


/* Check quoted strings and their escape sequences.  All bytes produced
 * by an escape sequence have to end up in the single data node of the
 * quoted string; malformed or truncated escapes are rejected with
 * GPG_ERR_SEXP_BAD_QUOTATION before any node is returned.  */
static void
check_quoting (void)
{
  static struct
  {
    const char *text;
    const unsigned char *expect;
    size_t expect_len;
  } good[] =
    {
      /* Simple single-character escapes.  */
      { "(\"\\b\\t\\v\\n\\f\\r\\\"\\'\\\\\")",
        (const unsigned char *)"\b\t\v\n\f\r\"'\\", 9 },
      /* Hexadecimal and octal escapes, also at the end of the buffer.  */
      { "(\"\\x41\\101\")",
        (const unsigned char *)"AA", 2 },
      /* Escaped quote and backslash stay inside the node.  */
      { "(\"a\\\"b\")",
        (const unsigned char *)"a\"b", 3 },
      /* Line continuations swallow the CR/LF pair.  */
      { "(\"a\\\r\nb\")",
        (const unsigned char *)"ab", 2 },
      { "(\"a\\\n\rb\")",
        (const unsigned char *)"ab", 2 },
    };
  static struct
  {
    const char *text;
    size_t length;
  } bad[] =
    {
      { "(\"\\q\")",   6 },  /* Unknown escape character.  */
      { "(\"\\x4\")",  7 },  /* Truncated hexadecimal escape.  */
      { "(\"\\xg\")",  7 },  /* Non hex digit in hex escape.  */
      { "(\"\\7\")",   6 },  /* Truncated octal escape.  */
    };
  int idx;
  gcry_sexp_t sexp;
  gpg_error_t err;

  info ("checking quoted strings and escape boundaries\n");

  for (idx = 0; idx < DIM (good); idx++)
    {
      size_t datalen;
      const char *data;

      sexp = NULL;
      err = gcry_sexp_sscan (&sexp, NULL, good[idx].text,
                             strlen (good[idx].text));
      if (err)
        {
          fail ("good quoting %d rejected: %s\n", idx, gpg_strerror (err));
          continue;
        }
      /* Everything must land in exactly one node.  */
      if (gcry_sexp_length (sexp) != 1)
        fail ("good quoting %d: expected a single node, got %d\n",
              idx, gcry_sexp_length (sexp));
      data = gcry_sexp_nth_data (sexp, 0, &datalen);
      if (!data)
        fail ("good quoting %d: no data node\n", idx);
      else if (datalen != good[idx].expect_len
               || memcmp (data, good[idx].expect, datalen))
        {
          size_t i;

          fail ("good quoting %d: unquoted content mismatch "
                "(got %u bytes)\n", idx, (unsigned int)datalen);
          for (i = 0; i < datalen; i++)
            fprintf (stderr, "  got[%u]=0x%02x\n", (unsigned int)i,
                     (unsigned char)data[i]);
        }
      gcry_sexp_release (sexp);
    }

  for (idx = 0; idx < DIM (bad); idx++)
    require_sscan_failure ("bad quoting", bad[idx].text, bad[idx].length,
                           GPG_ERR_SEXP_BAD_QUOTATION, (size_t)-1);

  /* Two adjacent quoted strings produce two separate nodes: escape
   * handling must never merge data across node boundaries.  */
  sexp = NULL;
  err = gcry_sexp_sscan (&sexp, NULL, "(\"x\" \"y\")", 9);
  if (err)
    fail ("two quoted nodes rejected: %s\n", gpg_strerror (err));
  else
    {
      size_t n0, n1;
      const char *d0 = gcry_sexp_nth_data (sexp, 0, &n0);
      const char *d1 = gcry_sexp_nth_data (sexp, 1, &n1);

      if (gcry_sexp_length (sexp) != 2 || !d0 || !d1
          || n0 != 1 || d0[0] != 'x' || n1 != 1 || d1[0] != 'y')
        fail ("two quoted nodes: node structure not preserved\n");
    }
  gcry_sexp_release (sexp);
}


/* After a failed parse the parser object/state must remain usable:
 * every call gets a fresh output handle, a failure leaves it NULL, and
 * subsequent calls on the same thread parse independent input
 * correctly.  This is run repeatedly so that resource leaks show up
 * under malloc debugging or sanitizers.  */
static void
check_parser_recovery (void)
{
  static struct
  {
    const char *text;
    gpg_err_code_t errcode;
  } bad[] =
    {
      { "(10:ab)",  GPG_ERR_SEXP_STRING_TOO_LONG },
      { "(01:x)",   GPG_ERR_SEXP_ZERO_PREFIX     },
      { "(3ax)",    GPG_ERR_SEXP_INV_LEN_SPEC    },
      { "((1:x)",   GPG_ERR_SEXP_UNMATCHED_PAREN },
      { "(\"\\q\")",GPG_ERR_SEXP_BAD_QUOTATION   },
    };
  static const char *good = "(2:ok)";
  int round, idx;
  gcry_sexp_t sexp;
  gpg_error_t err;
  size_t datalen;
  const char *data;

  info ("checking parser recovery after untrusted-input failures\n");

  for (round = 0; round < 32; round++)
    {
      for (idx = 0; idx < DIM (bad); idx++)
        {
          sexp = NULL;
          err = gcry_sexp_sscan (&sexp, NULL, bad[idx].text,
                                 strlen (bad[idx].text));
          if (gpg_err_code (err) != bad[idx].errcode)
            fail ("recovery round %d case %d: expected %d got %d (%s)\n",
                  round, idx, bad[idx].errcode, gpg_err_code (err),
                  gpg_strerror (err));
          if (sexp)
            {
              fail ("recovery round %d case %d: non-NULL handle on error\n",
                    round, idx);
              gcry_sexp_release (sexp);
            }

          /* The very next call must work on unrelated input.  */
          sexp = NULL;
          err = gcry_sexp_sscan (&sexp, NULL, good, strlen (good));
          if (err)
            fail ("recovery round %d case %d: follow-up parse failed: %s\n",
                  round, idx, gpg_strerror (err));
          else
            {
              data = gcry_sexp_nth_data (sexp, 0, &datalen);
              if (!data || datalen != 2 || memcmp (data, "ok", 2))
                fail ("recovery round %d case %d: follow-up data wrong\n",
                      round, idx);
              gcry_sexp_release (sexp);
            }
        }
    }
}


int
main (int argc, char **argv)
{
  int last_argc = -1;
  int loop = 0;

  if (argc)
    {
      argc--; argv++;
    }
  while (argc && last_argc != argc )
    {
      last_argc = argc;
      if (!strcmp (*argv, "--"))
        {
          argc--; argv++;
          break;
        }
      else if (!strcmp (*argv, "--help"))
        {
          puts (
"usage: " PGM " [options]\n"
"\n"
"Options:\n"
"  --verbose      Show what is going on\n"
"  --debug        Flyswatter\n"
);
          exit (0);
        }
      else if (!strcmp (*argv, "--verbose"))
        {
          verbose = 1;
          argc--; argv++;
        }
      else if (!strcmp (*argv, "--debug"))
        {
          verbose = debug = 1;
          argc--; argv++;
        }
      else if (!strcmp (*argv, "--loop"))
        {
          argc--; argv++;
          if (argc)
            {
              loop = atoi (*argv);
              argc--; argv++;
            }
        }
      else if (!strncmp (*argv, "--", 2))
        die ("unknown option '%s'", *argv);
    }

  if (debug)
    xgcry_control ((GCRYCTL_SET_DEBUG_FLAGS, 1u, 0));
  xgcry_control ((GCRYCTL_DISABLE_SECMEM_WARN));
  if (getenv ("GCRYPT_IN_ASAN_TEST"))
    {
      fputs ("Note: " PGM " not using secmem as running with ASAN.\n", stdout);
    }
  else
    {
      xgcry_control ((GCRYCTL_INIT_SECMEM, 16384, 0));
    }
  if (!gcry_check_version (GCRYPT_VERSION))
    die ("version mismatch");
  /* #include "../src/gcrypt-int.h" indicates that internal interfaces
     may be used; thus better do an exact version check. */
  if (strcmp (gcry_check_version (NULL), GCRYPT_VERSION))
    die ("exact version match failed");
  xgcry_control ((GCRYCTL_ENABLE_QUICK_RANDOM, 0));
  xgcry_control ((GCRYCTL_INITIALIZATION_FINISHED, 0));

  do
    {
      basic ();
      canon_len ();
      back_and_forth ();
      check_sscan ();
      check_extract_param ();
      bug_1594 ();
      check_nesting ();
      check_length_decl ();
      check_quoting ();
      check_parser_recovery ();
    }
  while (!error_count && loop--);

  return error_count? 1:0;
}
