#pragma once

#include "des.h"
#include <string>
#include <cstring>
#include "sha1.h"

#define SHA1_OUT_SIZE 20
#define B 512
#define B_BYTES B / 8
#define IPAD 0x36
#define OPAD 0x5C

using std::string;

string hmac(const string &message, const string &_key)
{
  SHA1 hasher;
  string key = hex2String(_key);

  unsigned char Si[B_BYTES] = {0};
  unsigned char S0[B_BYTES] = {0};
  if (key.size() <= B_BYTES)
  {
    memcpy(Si, key.c_str(), key.size());
  }
  else
  {
    hasher.add(key.c_str(), key.size());
    hasher.getHash(Si);
    hasher.reset();
  }

  for (int i = 0; i < B_BYTES; i++)
  {
    S0[i] = Si[i] ^ OPAD;
    Si[i] ^= IPAD;
  }

  unsigned char hashVal[SHA1_OUT_SIZE];

  hasher.add(Si, B_BYTES);
  hasher.add(message.c_str(), message.length());
  hasher.getHash(hashVal);

  hasher.reset();
  hasher.add(S0, B_BYTES);
  hasher.add(hashVal, SHA1_OUT_SIZE);

  return hasher.getHash();
}
