#include <iostream>
#include "desBlockModes.h"
#include "des.h"
using std::cout;
using std::endl;
int mainnn()
{
    //string message = "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF012345678";
    string key = "133457799BBCDFF1";
    string test = "HelloworldHelloworld";
    string IV = "133457799BBCDFF1";
    string counter = "1478523691abcdef";

    cout << test << endl;
    cout << string2Hex(IV) << endl;

    cout << "message is " << test << " key is " << key << endl;
    string cipher = CFB_E(test, key, IV);
    cout << "cipher is:" << cipher  << " and hex: " << string2Hex(cipher)<< endl;
    cout << "original ans is:" << CFB_D(cipher, key, IV) << endl;

    // string cases[] = {"0123456789ABCDEF", "02468aceeca86420", "6D6573736167652E"};
    // string keys[] = {"133457799BBCDFF1", "0f1571c947d9e859", "38627974656B6579"};

    // for (int i = 0; i < 3; i++)
    // {

    //     vector<string> keysV = desKeys(keys[i]);
    //     string outputS = desEnc(cases[i], keys[i]);

    //     cout << "Message: " << cases[i] << " Key: " << keys[i] << " des: " << outputS << endl;

    //     reverse(keysV.begin(), keysV.end());
    //     cout << "after decryption: " << desDec(outputS, keys[i]) << endl << endl;
    // }

    return 0;
}