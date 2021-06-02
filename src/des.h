#ifndef DES_H_ 
#define DES_H_ 
#include <string>
#include <unordered_map>
#include <vector>
#include <bitset>
#include <algorithm>

using namespace std;

string hex2Bin(string hex);
string permute(string key, int table[], int size);
vector<string> generate16Key(string key);
string roundLRK(string L, string R, string key);
string xorS(string s1, string s2);
string Sbox(string inp);
string bin2Hex(string bin);
vector<string> desKeys(string key);
string des(string msg, vector<string> keysVector);
#endif