#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "../sign.h"
#include "../poly.h"
#include "../polyvec.h"
#include "../params.h"
#include "cpucycles.h"
#include "speed_print.h"

#define NTESTS 1000
#define MLEN 256      /* buffer capacity for the manually-entered message */

uint64_t t[NTESTS];

int main(void)
{
  unsigned int i;
  size_t siglen;
  size_t mlen;
  uint8_t pk[CRYPTO_PUBLICKEYBYTES];
  uint8_t sk[CRYPTO_SECRETKEYBYTES];
  uint8_t sig[CRYPTO_BYTES];
  uint8_t seed[CRHBYTES];
  uint8_t m[MLEN];
  polyvecl mat[K];
  poly *a = &mat[0].vec[0];
  poly *b = &mat[0].vec[1];
  poly *c = &mat[0].vec[2];

  /* Read the message to benchmark signing/verification with. */
  printf("Enter message to sign: ");
  fflush(stdout);
  if(!fgets((char*)m, MLEN, stdin)) {
    fprintf(stderr, "Failed to read message\n");
    return -1;
  }
  mlen = strlen((char*)m);
  if(mlen > 0 && m[mlen-1] == '\n')  /* strip trailing newline */
    m[--mlen] = 0;
  printf("Message length = %zu bytes\n", mlen);

  for(i = 0; i < NTESTS; ++i) {
    t[i] = cpucycles();
    polyvec_matrix_expand(mat, seed);
  }
  print_results("polyvec_matrix_expand:", t, NTESTS);

  for(i = 0; i < NTESTS; ++i) {
    t[i] = cpucycles();
    poly_uniform_eta(a, seed, 0);
  }
  print_results("poly_uniform_eta:", t, NTESTS);

  for(i = 0; i < NTESTS; ++i) {
    t[i] = cpucycles();
    poly_uniform_gamma1(a, seed, 0);
  }
  print_results("poly_uniform_gamma1:", t, NTESTS);

  for(i = 0; i < NTESTS; ++i) {
    t[i] = cpucycles();
    poly_ntt(a);
  }
  print_results("poly_ntt:", t, NTESTS);

  for(i = 0; i < NTESTS; ++i) {
    t[i] = cpucycles();
    poly_invntt_tomont(a);
  }
  print_results("poly_invntt_tomont:", t, NTESTS);

  for(i = 0; i < NTESTS; ++i) {
    t[i] = cpucycles();
    poly_pointwise_montgomery(c, a, b);
  }
  print_results("poly_pointwise_montgomery:", t, NTESTS);

  for(i = 0; i < NTESTS; ++i) {
    t[i] = cpucycles();
    poly_challenge(c, seed);
  }
  print_results("poly_challenge:", t, NTESTS);

  for(i = 0; i < NTESTS; ++i) {
    t[i] = cpucycles();
    crypto_sign_keypair(pk, sk);
  }
  print_results("Keypair:", t, NTESTS);

  for(i = 0; i < NTESTS; ++i) {
    t[i] = cpucycles();
    crypto_sign_signature(sig, &siglen, m, mlen, NULL, 0, sk);
  }
  print_results("Sign:", t, NTESTS);

  for(i = 0; i < NTESTS; ++i) {
    t[i] = cpucycles();
    crypto_sign_verify(sig, CRYPTO_BYTES, m, mlen, NULL, 0, pk);
  }
  print_results("Verify:", t, NTESTS);

  return 0;
}
