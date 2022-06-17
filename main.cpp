#include "include/ed25519/ed25519.h"
#include "include/sha256/sha256.h"
#include "include/base64/base64.h"
#include <curl/curl.h>
#include <stdlib.h>
#include <assert.h>
#include <unordered_map>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

// We don't need Ed25519 key generation
#define ED25519_NO_SEED

// trim removes whitespace and newline characters from a string.
inline std::string trim(std::string str, std::string chars = " \t\n\r\f\v")
{
  str.erase(str.find_last_not_of(chars) + 1);
  str.erase(0, str.find_first_not_of(chars));

  return str;
}

// lower converts a string to lowercase.
inline std::string lower(std::string str)
{
  std::transform(str.cbegin(), str.cend(), str.begin(), [](unsigned char c) { return std::tolower(c); });

  return str;
}

// split splits a string by delimiter into a vector of strings.
inline std::vector<std::string> split(std::string str, std::string delim, int n = 0)
{
  std::vector<std::string> vec;
  size_t pos;

  // Keep track of iterations for n
  int i = 0;

  while ((n == 0 || (n > 0 && i < n - 1)) && (pos = str.find(delim)) != std::string::npos)
  {
    vec.push_back(str.substr(0, pos));

    str = str.substr(pos + delim.size());

    i++;
  }

  vec.push_back(str); // Last word

  return vec;
}

// sha256 calculates the SHA256 digest of a string, returning a base64 encoded string.
inline std::string sha256(std::string str)
{
  uint8_t digest[32];
  int l;

  sha256_easy_hash(str.c_str(), str.size(), digest);

  char* enc = base64(digest, 32, &l);

  return std::string(enc);
}

// unhex convert a hex string to raw bytes.
inline void unhex(std::string str, unsigned char* bytes)
{
  std::stringstream converter;

  for (int i = 0; i < str.size(); i += 2)
  {
    int byte;

    converter << std::hex << str.substr(i, 2);
    converter >> byte;

    bytes[i / 2] = byte & 0xff;

    converter.str(std::string());
    converter.clear();
  }
}

// colorize adds ANSII color codes to a string.
inline std::string colorize(const std::string str, const int color_code)
{
  std::stringstream stream;

  stream << "\033[1;";
  stream << color_code;
  stream << "m";
  stream << str;
  stream << "\033[0m";

  return stream.str();
}

// signature represents a parsed response signature (https://keygen.sh/docs/api/signatures/#response-signatures).
struct signature
{
  std::string keyid;
  std::string algorithm;
  std::string signature;
  std::string headers;
};

// request represents an API request.
struct request
{
  std::string host;
  std::string method;
  std::string path;
};

// response represents an API response.
struct response
{
  request request;
  int status;
  std::unordered_map<std::string, std::string> headers;
  std::string body;
  signature signature;
  std::string digest;
  std::string date;
};

// write_fn handles writing a curl response's body into a response.
size_t write_fn(const char* ptr, size_t size, size_t nmemb, void* data)
{
  response& res = *reinterpret_cast<response*>(data);

  res.body.insert(res.body.end(), ptr, ptr + size * nmemb);

  return nmemb;
}

// header_fn handles writing a curl response's status and headers into a response.
size_t header_fn(const char* ptr, size_t size, size_t nmemb, void* data)
{
  response& res = *reinterpret_cast<response*>(data);

  auto bytes = size * nmemb;
  auto end = ptr + bytes;

  if (bytes > 7 && std::string(ptr, ptr + 7) == "HTTP/1.")
  {
    if (bytes >= 12)
    {
      res.headers.clear();
      res.status = std::stoi(std::string(ptr + 9, ptr + 12));
    }
    else
    {
      res.status = -1;
    }
  }
  else
  {
    auto sep = std::find(ptr, end, ':');
    if (sep != end)
    {
      std::string key = std::string(ptr, sep);
      std::string value(sep + 1, end);

      // Lowercase header keys
      key = lower(key);

      // Trim whitespace and newlines
      value = trim(value);

      res.headers[key] = std::move(value);
    }
  }

  return nmemb;
}

// do_request sends an API request.
response do_request(const std::string account_id, const std::string token, std::string path)
{
  static const std::string host = "api.keygen.sh";
  static const std::string method = "GET";

  // Ensure path has a leading slash
  if (path.at(0) != '/')
  {
    path = '/' + path;
  }

  // Fully qualified path
  path = "/v1/accounts/" + account_id + path;

  // Perform the request
  request req {host, method, path};
  response res {req};

  auto curl = curl_easy_init();
  if (curl)
  {
    curl_easy_setopt(curl, CURLOPT_URL, ("https://" + host + path).c_str());

    curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, header_fn);
    curl_easy_setopt(curl, CURLOPT_WRITEHEADER, reinterpret_cast<void*>(&res));

    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_fn);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, reinterpret_cast<void*>(&res));

    auto headers = curl_slist_append(nullptr, ("Authorization: Bearer " + token).c_str());
    headers = curl_slist_append(headers, "Accept: application/json");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

    auto res = curl_easy_perform(curl);
    curl_easy_cleanup(curl);
  }

  // Parse signature header
  if (res.headers.count("keygen-signature") > 0)
  {
    signature sig;

    for (auto &param: split(res.headers["keygen-signature"], ", "))
    {
      auto kv = split(param, "=", 2);
      auto k = trim(kv[0], " ");
      auto v = trim(kv[1], "\"");

      if (k == "keyid")
      {
        sig.keyid = v;
      }

      if (k == "algorithm")
      {
        sig.algorithm = v;
      }

      if (k == "signature")
      {
        sig.signature = v;
      }

      if (k == "headers")
      {
        sig.headers = v;
      }
    }

    res.signature = sig;
  }

  // Convenience fields
  res.digest = res.headers["digest"];
  res.date = res.headers["date"];

  return res;
}

// verify_response verifies a response's cryptographic signature using Ed25519.
bool verify_response(const std::string pubkey, response res)
{
  if (res.signature.algorithm != "ed25519")
  {
    return false;
  }

  // Recreate signing data for signature
  std::stringstream stream;

  stream << "(request-target): " << lower(res.request.method) << " " << lower(res.request.path) << "\n"
         << "host: " << res.request.host << "\n"
         << "date: " << res.date << "\n"
         << "digest: sha-256=" << sha256(res.body);

  // Convert signing data into bytes
  auto data = stream.str();
  auto data_bytes = reinterpret_cast<const unsigned char*>(data.c_str());
  auto data_size = data.size();

  // Decode signature into bytes
  auto sig = res.signature.signature;
  int sig_size;

  unsigned char* sig_bytes = unbase64(sig.c_str(), sig.size(), &sig_size);

  // Decode hex public key into bytes
  unsigned char key_bytes[32];

  unhex(pubkey, key_bytes);

  // Verify signature
  auto ok = ed25519_verify(sig_bytes, data_bytes, data_size, key_bytes);

  return (bool) ok;
}

// main runs the example program.
int main(int argc, char* argv[])
{
  if (argc != 2)
  {
    std::cerr << colorize("[ERROR]", 31) << " "
              << "No path given"
              << std::endl;

    return 1;
  }

  if (!getenv("KEYGEN_PUBLIC_KEY"))
  {
    std::cerr << colorize("[ERROR]", 31) << " "
              << "Environment variable KEYGEN_PUBLIC_KEY is missing"
              << std::endl;

    return 1;
  }

  if (!getenv("KEYGEN_ACCOUNT"))
  {
    std::cerr << colorize("[ERROR]", 31) << " "
              << "Environment variable KEYGEN_ACCOUNT is missing"
              << std::endl;

    return 1;
  }

  if (!getenv("KEYGEN_TOKEN"))
  {
    std::cerr << colorize("[ERROR]", 31) << " "
              << "Environment variable KEYGEN_TOKEN is missing"
              << std::endl;

    return 1;
  }

  std::string pubkey = getenv("KEYGEN_PUBLIC_KEY");
  std::string account = getenv("KEYGEN_ACCOUNT");
  std::string token = getenv("KEYGEN_TOKEN");
  std::string path = argv[1];

  // Perform the request
  auto res = do_request(account, token, path);

  std::cout << "host=" << colorize(res.request.host, 34) << "\n"
            << "method=" << colorize(res.request.method, 34) << "\n"
            << "path=" << colorize(res.request.path, 34) << "\n"
            << "status=" << colorize(std::to_string(res.status), 34) << "\n"
            << "date=" << colorize(res.date, 34) << "\n"
            << "signature=" << colorize(res.signature.signature, 34) << "\n"
            << "algorithm=" << colorize(res.signature.algorithm, 34) << "\n"
            << "digest=" << colorize(res.digest, 34) << "\n"
            << "body=" << colorize(res.body, 34)
            << std::endl;

  // Verify the response signature
  bool ok = verify_response(pubkey, res);
  if (ok)
  {
    std::cout << colorize("[OK]", 32) << " "
              << "Signature is valid!"
              << std::endl;

    return 0;
  }
  else
  {
    std::cerr << colorize("[ERROR]", 31) << " "
              << "Signature is not valid!"
              << std::endl;

    return 1;
  }
}
