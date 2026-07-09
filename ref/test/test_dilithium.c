#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../randombytes.h"
#include "../sign.h"

#define MLEN 1024        /* buffer capacity for manually-entered messages */
#define CTXLEN 14
#define SELFTEST_MLEN 59  /* fixed random-message length for the self-test  */
#define NTESTS 10000      /* iterations in the automated self-test          */

/* Read a line from stdin into buf (max buflen-1 chars), strip the trailing
   newline, and return the resulting message length. */
static size_t read_message(const char *prompt, uint8_t *buf, size_t buflen)
{
  size_t len;
  printf("%s", prompt);
  fflush(stdout);
  if(!fgets((char*)buf, (int)buflen, stdin)) {
    fprintf(stderr, "Failed to read message\n");
    exit(-1);
  }
  len = strlen((char*)buf);
  if(len > 0 && buf[len-1] == '\n')  /* strip trailing newline */
    buf[--len] = 0;
  return len;
}

/* Interactive mode: sign a typed message, then verify a (possibly different)
   typed message against the detached signature and report VALID/INVALID. */
static int run_manual(void)
{
  int ret;
  size_t mlen, vlen, siglen;
  uint8_t ctx[CTXLEN] = {0};
  uint8_t m[MLEN];                   /* message that gets signed  */
  uint8_t v[MLEN];                   /* message checked at verify */
  uint8_t sig[CRYPTO_BYTES];         /* detached signature        */
  uint8_t pk[CRYPTO_PUBLICKEYBYTES];
  uint8_t sk[CRYPTO_SECRETKEYBYTES];

  snprintf((char*)ctx,CTXLEN,"test_dilitium");

  /* ---- Signing: message typed by the user ---- */
  mlen = read_message("Enter message to SIGN: ", m, MLEN);
  printf("Signed message length = %zu bytes\n", mlen);

  crypto_sign_keypair(pk, sk);
  crypto_sign_signature(sig, &siglen, m, mlen, ctx, CTXLEN, sk);
  printf("Signature generated (%zu bytes).\n\n", siglen);

  /* ---- Verifying: message typed by the user (independently) ---- */
  vlen = read_message("Enter message to VERIFY against the signature: ", v, MLEN);

  ret = crypto_sign_verify(sig, siglen, v, vlen, ctx, CTXLEN, pk);

  if(ret == 0)
    printf("\nRESULT: VALID  - the message matches the signature.\n");
  else
    printf("\nRESULT: INVALID - the message does NOT match the signature.\n");

  printf("\nCRYPTO_PUBLICKEYBYTES = %d\n", CRYPTO_PUBLICKEYBYTES);
  printf("CRYPTO_SECRETKEYBYTES = %d\n", CRYPTO_SECRETKEYBYTES);
  printf("CRYPTO_BYTES = %d\n", CRYPTO_BYTES);

  return 0;
}

/* Automated self-test: the original harness. Over NTESTS iterations it signs a
   fresh random message, checks the round-trip (lengths + byte-exact recovery),
   then tampers with one signature byte and confirms verification now fails. */
static int run_selftest(void)
{
  size_t i, j;
  int ret;
  size_t mlen, smlen;
  uint8_t b;
  uint8_t ctx[CTXLEN] = {0};
  uint8_t m[SELFTEST_MLEN + CRYPTO_BYTES];
  uint8_t m2[SELFTEST_MLEN + CRYPTO_BYTES];
  uint8_t sm[SELFTEST_MLEN + CRYPTO_BYTES];
  uint8_t pk[CRYPTO_PUBLICKEYBYTES];
  uint8_t sk[CRYPTO_SECRETKEYBYTES];

  snprintf((char*)ctx,CTXLEN,"test_dilitium");

  printf("Running self-test: %d iterations of keygen/sign/verify + forgery check...\n",
         NTESTS);

  for(i = 0; i < NTESTS; ++i) {
    randombytes(m, SELFTEST_MLEN);

    crypto_sign_keypair(pk, sk);
    crypto_sign(sm, &smlen, m, SELFTEST_MLEN, ctx, CTXLEN, sk);
    ret = crypto_sign_open(m2, &mlen, sm, smlen, ctx, CTXLEN, pk);

    if(ret) {
      fprintf(stderr, "Verification failed\n");
      return -1;
    }
    if(smlen != SELFTEST_MLEN + CRYPTO_BYTES) {
      fprintf(stderr, "Signed message lengths wrong\n");
      return -1;
    }
    if(mlen != SELFTEST_MLEN) {
      fprintf(stderr, "Message lengths wrong\n");
      return -1;
    }
    for(j = 0; j < SELFTEST_MLEN; ++j) {
      if(m2[j] != m[j]) {
        fprintf(stderr, "Messages don't match\n");
        return -1;
      }
    }

    randombytes((uint8_t *)&j, sizeof(j));
    do {
      randombytes(&b, 1);
    } while(!b);
    sm[j % (SELFTEST_MLEN + CRYPTO_BYTES)] += b;
    ret = crypto_sign_open(m2, &mlen, sm, smlen, ctx, CTXLEN, pk);
    if(!ret) {
      fprintf(stderr, "Trivial forgeries possible\n");
      return -1;
    }
  }

  printf("All %d sign/verify round-trips and forgery checks passed.\n\n", NTESTS);
  printf("CRYPTO_PUBLICKEYBYTES = %d\n", CRYPTO_PUBLICKEYBYTES);
  printf("CRYPTO_SECRETKEYBYTES = %d\n", CRYPTO_SECRETKEYBYTES);
  printf("CRYPTO_BYTES = %d\n", CRYPTO_BYTES);

  return 0;
}

int main(int argc, char *argv[])
{
  if(argc > 1 && strcmp(argv[1], "selftest") == 0)
    return run_selftest();

  return run_manual();
}
