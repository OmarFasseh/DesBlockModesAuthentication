#include <cstdio>
#include <cstring>
#include "md5.hh"
#include<string>
#include"desBlockModes.h"
#include"des.h"
using namespace std;
int main() {
   	string k = "0000000000000000";
	string message = "hellowor";
	string ipad="3636363636363636";
	string opad = "5c5c5c5c5c5c5c5c";
	string si = bin2Hex(xorS(hex2Bin(k), hex2Bin(ipad)));
	
	
	message = hex2String(si) + message;
	message = string2Hex(message);
	string hash = md5sum(message.c_str(), strlen(message.c_str()));
	
	
	string so = bin2Hex(xorS(hex2Bin(k), hex2Bin(opad)));
	hash = hex2String(so) + hex2String(hash);
	string HMAC = md5sum(hash.c_str(), strlen(hash.c_str()));
	//cout << HMAC;
	return 0 ;
}