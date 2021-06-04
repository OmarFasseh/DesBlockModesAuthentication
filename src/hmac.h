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

string hmac(const string &data, const string &_key)
{
  SHA1 hasher;
  string key = hex2String(_key);

  unsigned char bbitKey1[B_BYTES] = {0};
  unsigned char bbitKey2[B_BYTES] = {0};
  if (key.size() <= B_BYTES)
  {
    memcpy(bbitKey1, key.c_str(), key.size());
  }
  else
  {
    hasher.add(key.c_str(), key.size());
    hasher.getHash(bbitKey1);
    hasher.reset();
  }

  for (int i = 0; i < B_BYTES; i++)
  {
    bbitKey2[i] = bbitKey1[i] ^ OPAD;
    bbitKey1[i] ^= IPAD;
  }

  unsigned char hashVal[SHA1_OUT_SIZE];

  hasher.add(bbitKey1, B_BYTES);
  hasher.add(data.c_str(), data.length());
  hasher.getHash(hashVal);

  hasher.reset();
  hasher.add(bbitKey2, B_BYTES);
  hasher.add(hashVal, SHA1_OUT_SIZE);

  return hasher.getHash();
}
