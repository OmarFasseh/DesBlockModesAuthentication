#include <cstdio>
#include <cstring>
#include <iostream>
#include "md5.hh"
#include <string>
#include "sha1.hpp"
#include "desBlockModes.h"
#include "des.h"
using namespace std;

#define B 512
#define BHex 128

int main()
{

	SHA1 checksum;
	// checksum.update("tmp");
	// string hash = checksum.final();
	// checksum.update("tmp2");
	// cout <<" t1 " <<hash <<endl;
	// hash = checksum.final();
	// cout <<" t1 " <<hash <<endl;



	string k = "10000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001";
	string message = "helloworldhelloworldhelloworldhelloworldhelloworldhelloworld1234";
	string ipad = "36363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636";
	string opad = "5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c";
	string si = bin2Hex(xorS(hex2Bin(k), hex2Bin(ipad)));

	string tmp;
	message = hex2String(si) + message;
	//message = string2Hex(message);
	cout << si << "   " << message << endl;

	checksum.update(message);
	string hash = checksum.final();
	// hash = md5sum(message.c_str(), message.length());
	cout << "hash: " << hash << endl;
	hash = string(BHex-hash.size(), '0') + hash;
	cout << "after padding: " << hash << endl;

	string so = bin2Hex(xorS(hex2Bin(k), hex2Bin(opad)));
	tmp = hex2String(so+hash);
	checksum.update(tmp);
	//const string hash = checksum.final();
	//string HMAC = md5sum(hash.c_str(), strlen(hash.c_str()));
	cout << checksum.final() << endl;
	//cout << HMAC << endl;
	return 0;
}