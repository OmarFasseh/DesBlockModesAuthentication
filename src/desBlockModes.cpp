#include <string>

#include <algorithm>
#include <sstream>

#include "desBlockModes.h"
#include "des.h"

#define PADCHAR " "
#define CFB_S 8 //multiples of 4
using std::string;



void blockPadding(string& s)
{
    int rem = s.size() % 8;
    if (rem)
    {
        for (int i = rem; i < 8; i++)
        {
            s += PADCHAR;
        }
    }
}

//shifts string n bits left and adds s2 from the right
string shitfHexNbits(const string& hex, int n, const string& s2)
{
    string bin = hex2Bin(hex);
    string bin2 = hex2Bin(s2);
    string ans = bin.substr(n, bin.size() - n);
    for (int j = 0; j < n; j++)
    {
        ans += bin2[j];
    }
    ans = bin2Hex(ans);
    return ans;
}

//hex input
string desEnc(string message, string key)
{
    vector<string> roundskeys;
    roundskeys = desKeys(key);
    return des(message, roundskeys);
}
//hex input
string desDec(string message, string key)
{
    vector<string> roundskeys;
    roundskeys = desKeys(key);
    reverse(roundskeys.begin(), roundskeys.end());
    return des(message, roundskeys);
}

//string input, hex key
string ECB_E(string s, const string& key)
{

    blockPadding(s);
    s = string2Hex(s);
    string tmp, ans = "";
    for (int i = 0; i < s.size(); i += 16)
    {
        tmp = s.substr(i, 16);
        ans += (desEnc(tmp, key));
    }
    return hex2String(ans);
}

//string input, hex key
string ECB_D(string s, const string& key)
{
    string tmp, ans = "";
    s = string2Hex(s);
    for (int i = 0; i < s.size(); i += 16)
    {
        tmp = s.substr(i, 16);
        ans += desDec((tmp), key);
    }
    return hex2String(ans);
}

//string input, hex key
string CBC_E(string s, const string& key, const string& IV)
{
    string Cn, Pn, tmp, ans = "";
    blockPadding(s);
    s = string2Hex(s);
    Pn = s.substr(0, 16);
    tmp = bin2Hex(xorS(hex2Bin(Pn), hex2Bin(IV)));
    Cn = (desEnc(tmp, key));
    ans += Cn;
    for (int i = 16; i < s.size(); i += 16)
    {
        Pn = s.substr(i, 16);
        string tmp = bin2Hex(xorS(hex2Bin(Pn), hex2Bin(Cn)));
        Cn = (desEnc(tmp, key));
        ans += Cn;
    }
    return hex2String(ans);
}
//string input, hex key, string IV
string CBC_D(string s, const string& key, const string& IV)
{
    string prev, tmp, Cn, ans = "";
    s = string2Hex(s);
    Cn = s.substr(0, 16);
    int cnsize = Cn.size();
    tmp = desDec(Cn, key);
    ans += bin2Hex(xorS(hex2Bin(tmp), hex2Bin(IV)));
    prev = Cn;
    for (int i = 16; i < s.size(); i += 16)
    {
        Cn = s.substr(i, 16);
        cnsize = Cn.size();
        tmp = desDec(Cn, key);
        ans += bin2Hex(xorS(hex2Bin(tmp), hex2Bin(prev)));
        prev = Cn;
    }
    return hex2String(ans);
}

//string input, hex key ,hex counter
string CTR_ED(string s, const string& key, string counter)
{
    
    string temp, Pn, Cn, ans = "";
    //blockPadding(s);
    s = string2Hex(s);
    long long x;
    std::stringstream ss;
    ss << std::hex << counter;
    ss >> x;
    for (int i = 0; i < s.size(); i += 16)
    {
        temp = desEnc(counter, key);
        Pn = s.substr(i, 16);
        Cn = bin2Hex(xorS(hex2Bin(Pn), hex2Bin(temp)));
        ans += Cn;
        x += 1;
        std::stringstream stream;
        stream << std::hex << x;
        counter = stream.str();
    }
    return hex2String(ans);
}


//string input, hex key, string IV
string CFB_E(string s, const string& key, const string& IV)
{
    int sBits = CFB_S; //multiples of 4
    string temp, Pn, Cn, ans = "";
    blockPadding(s);
    s = string2Hex(s);
    string shiftReg = IV;

    temp = desEnc(shiftReg, key);
    Pn = s.substr(0, sBits / 4);
    Cn = bin2Hex(xorS(hex2Bin(temp.substr(0, sBits / 4)), hex2Bin(Pn)));
    ans += Cn;
    for (int i = sBits / 4; i < s.size(); i += sBits / 4)
    {
        shiftReg = shitfHexNbits(shiftReg, sBits, Cn);
        temp = desEnc(shiftReg, key);
        Pn = s.substr(i, sBits / 4);
        Cn = bin2Hex(xorS(hex2Bin(temp.substr(0, sBits / 4)), hex2Bin(Pn)));
        ans += Cn;
    }
    return hex2String(ans);
}

//string input, hex key, string IV
string CFB_D(string s, const string& key, const string& IV)
{
    int sBits = CFB_S; //multiples of 4
    string temp, Pn, Cn, ans = "";
    s = string2Hex(s);
    string shiftReg = IV;

    temp = desEnc(shiftReg, key);
    Cn = s.substr(0, sBits / 4);
    Pn = bin2Hex(xorS(hex2Bin(temp.substr(0, sBits / 4)), hex2Bin(Cn)));
    ans += Pn;
    for (int i = sBits / 4; i < s.size(); i += sBits / 4)
    {
        shiftReg = shitfHexNbits(shiftReg, sBits, Cn);
        temp = desEnc(shiftReg, key);
        Cn = s.substr(i, sBits / 4);
        Pn = bin2Hex(xorS(hex2Bin(temp.substr(0, sBits / 4)), hex2Bin(Cn)));
        ans += Pn;
    }
    return hex2String(ans);
}


