#include "des.h"
#include <string>
#include <unordered_map>
#include <vector>
#include <bitset>
#include <algorithm>
#include "desTables.h"
#include <iostream>
using namespace std;

string string2Hex(const string &input)
{
    static const char hex_digits[] = "0123456789ABCDEF";
    string output;
    output.reserve(input.length() * 2);
    for (unsigned char c : input)
    {
        output.push_back(hex_digits[c >> 4]);
        output.push_back(hex_digits[c & 15]);
    }
    return output;
}
string hex2String(const string &h)
{
    string tmp;
    string ans = "";
    try
    {
        for (int i = 0; i < h.size(); i += 2)
        {
            tmp = h.substr(i, 2);
            ans += (char)stoul(tmp, nullptr, 16);
        }
    }
    catch (const std::exception &e)
    {
        std::cerr << e.what() << " error key not hex value." <<  '\n';
    }
    return ans;
}

string hex2Bin(string hex)
{
    string bin = "";
    for (int i = 0; i < hex.size(); i++)
    {

        char c = tolower(hex[i]);
        bin += mapH2B[c];
    }

    return bin;
}

string bin2Hex(string bin)
{
    string hex = "";
    for (int i = 0; i < bin.size(); i += 4)
    {
        string c = "";
        c += bin[i];
        c += bin[i + 1];
        c += bin[i + 2];
        c += bin[i + 3];
        hex += mapB2H[c];
    }

    return hex;
}
string permute(string key, int table[], int size)
{
    string pkey = "";
    for (int i = 0; i < size; i++)
    {
        pkey += key[table[i] - 1];
    }
    return pkey;
}

vector<string> generate16Key(string key)
{
    vector<string> keys;
    keys.push_back(key);
    for (int i = 0; i < 16; i++)
    {
        string newkey = key.substr(keyShifts[i], key.size() - keyShifts[i]);
        for (int j = 0; j < keyShifts[i]; j++)
        {
            newkey += key[j];
        }

        keys.push_back(newkey);
        key = newkey;
    }

    return keys;
}

string roundLRK(string L, string R, string key)
{
    string E = "";
    for (int i = 0; i < 48; i++)
    {
        E += R[expansionTable[i] - 1];
    }

    string sOut = Sbox(xorS(E, key));
    string pOut = "";
    for (int i = 0; i < 32; i++)
    {
        pOut += sOut[pTable[i] - 1];
    }
    string Ri = xorS(L, pOut);
    return Ri;
}
string Sbox(string inp)
{
    string ans = "";
    for (int i = 0; i < 8; i++)
    {
        string s = inp.substr(i * 6, 6);
        string tmp = "";
        tmp += s[0];
        tmp += s[5];
        bitset<2> row(tmp);
        bitset<4> col(s.substr(1, 4));
        bitset<4> sOut(sBoxes[i][row.to_ulong()][col.to_ulong()]);
        ans += sOut.to_string();
    }
    return ans;
}
string xorS(string s1, string s2)
{
    //assume same size
    string ans = "";
    int n = min(s1.size(), s2.size());

    for (int i = 0; i < n; i++)
    {
        if (s1[i] == s2[i])
            ans += "0";
        else
            ans += "1";
    }
    return ans;
}

vector<string> desKeys(string key)
{
    string pKey = permute(hex2Bin(key), pc1Table, 56);
    string C0 = pKey.substr(0, 28);
    string D0 = pKey.substr(28, 28);
    vector<string> cVector = generate16Key(C0);
    vector<string> dVector = generate16Key(D0);
    vector<string> keysVector;

    for (int i = 1; i <= 16; i++)
    {
        keysVector.push_back(permute(cVector[i] + dVector[i], pc2Table, 48));
    }
    return keysVector;
}
string des(string msg, vector<string> keysVector)
{

    string pMsg = permute(hex2Bin(msg), initPTable, 64);
    string L0 = pMsg.substr(0, 32);
    string R0 = pMsg.substr(32, 64);
    string R1 = roundLRK(L0, R0, keysVector[0]);
    L0 = R0;
    R0 = R1;
    for (int i = 1; i < 16; i++)
    {

        string R1 = roundLRK(L0, R0, keysVector[i]);
        L0 = R0;
        R0 = R1;
    }
    return bin2Hex(permute(R0 + L0, finalPTable, 64));
}