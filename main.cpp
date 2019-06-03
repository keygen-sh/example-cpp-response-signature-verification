#include "include/base64.h"
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/bio.h>
#include <stdlib.h>
#include <assert.h>
#include <iostream>
#include <sstream>
#include <string>

using namespace std;

// Add ANSII color codes to string
string ansii_color_str(const string str, const int color_code)
{
  ostringstream stream;

  stream << "\033[1;";
  stream << color_code;
  stream << "m";
  stream << str;
  stream << "\033[0m";

  return stream.str();
}

// Load an RSA public key from a PEM string
RSA* load_rsa_pubic_key_from_pem(const string pem_pub_key)
{
  BIO* bio = BIO_new_mem_buf(pem_pub_key.c_str(), -1);
  BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);

  RSA* rsa = PEM_read_bio_RSA_PUBKEY(bio, nullptr, nullptr, nullptr);
  if (!rsa)
  {
    cerr << ansii_color_str("[ERROR]", 31) << " "
         << "Failed to load public key"
         << endl;

    exit(1);
  }

  // Should always be a 2048-bit public key
  assert(2048/8 == RSA_size(rsa));

  BIO_free(bio);

  return rsa;
}

// Verify a request body's cryptographic signature
bool verify_request_signature(RSA* rsa, const string body, const string sig)
{
  int body_len = body.size();
  unsigned char* body_buf = reinterpret_cast<unsigned char *>(
    const_cast<char *>(body.c_str())
  );

  // Base64 decode signature
  int sig_len;
  unsigned char* sig_buf = unbase64(sig.c_str(), sig.size(), &sig_len);

  // Hash request body using SHA256
  unsigned char body_digest[SHA256_DIGEST_LENGTH];
  SHA256(body_buf, body_len, body_digest);

  // Verify the request body's signature
  int res = RSA_verify(
    NID_sha256,
    body_digest,
    SHA256_DIGEST_LENGTH,
    sig_buf,
    sig_len,
    rsa
  );

  RSA_free(rsa);

  free(sig_buf);

  return (bool) res;
}

int main(int argc, char* argv[])
{
  if (argc != 3)
  {
    cerr << ansii_color_str("[ERROR]", 31) << " "
         << "No request body or signature argument(s) specified"
         << endl;

    exit(1);
  }

  string pem_pub_key = getenv("KEYGEN_PUBLIC_KEY");
  RSA* rsa = load_rsa_pubic_key_from_pem(pem_pub_key);

  string body = argv[1];
  string sig = argv[2];

  bool res = verify_request_signature(rsa, body, sig);
  if (res)
  {
    cout << ansii_color_str("[OK]", 32) << " "
         << "Signature is valid!"
         << endl;
  }
  else
  {
    cerr << ansii_color_str("[ERROR]", 31) << " "
         << "Signature is not valid!"
         << endl;
  }
}