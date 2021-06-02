#ifndef DESBLOCKMODES_H_  
#define DESBLOCKMODES_H_ 

#include <string>
using std::string;

string string2Hex(const string& input);
string hex2String(const string& h);
void blockPadding(string& s);
//shifts string n bits left and adds s2 from the right
string shitfHexNbits(const string& hex, int n, const string& s2);

//hex input
string desEnc(string message, string key);
//hex input
string desDec(string message, string key);

//string input, hex key
string ECB_E(string s, const string& key);
//string input, hex key
string ECB_D(string s, const string& key);

//string input, hex key ,hex counter
string CBC_E(string s, const string& key, const string& IV);
//string input, hex key, string IV
string CBC_D(string s, const string& key, const string& IV);

//string input, hex key ,hex counter
string CTR(string s, const string& key, string counter);

//string input, hex key, string IV
string CFB_E(string s, const string& key, const string& IV);
//string input, hex key, string IV
string CFB_D(string s, const string& key, const string& IV);


#endif