#include <iostream>
#include "desBlockModes.h"
#include "des.h"
using std::cout;
using std::endl;

#include <time.h>
#include <chrono>
using namespace std::chrono;
int main()
{
    //string message = "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF012345678";
    string key = "433b37ec76d68bdf";
    string test = "Hi there";
    string IV = "69375d7d0c0f1cd5";
    string counter = "d0560e20b816ca3a";

    cout << test << endl;
    cout << string2Hex(IV) << endl;

    cout << "message is " << test << " key is " << key << endl;
    string cipher = CFB_E(test, key, IV);
    cout << "cipher is:" << cipher << " and hex: " << string2Hex(cipher) << endl;
    cout << "original ans is:" << CFB_D(cipher, key, IV) << endl;
    int blockCount = 1;
    for (int i = 0; i < 15; i++)
    {
        cout << "\n \nNumber of blocks ="<<blockCount<< endl;
        //ecb
        auto start = high_resolution_clock::now();
        ECB_E(test, key);
        auto stop = high_resolution_clock::now();
        auto duration = duration_cast<milliseconds>(stop - start);
        cout << "ECB: "<< duration.count()<<"ms" << endl;
        //cbc
        start = high_resolution_clock::now();
        CBC_E(test, key, IV);
        stop = high_resolution_clock::now();
        duration = duration_cast<milliseconds>(stop - start);
        cout <<"CBC: "<<  duration.count()<<"ms" << endl;
        //cfb
        start = high_resolution_clock::now();
        CFB_E(test, key, IV);
        stop = high_resolution_clock::now();
        duration = duration_cast<milliseconds>(stop - start);
        cout <<"CFB: "<<  duration.count()<<"ms" << endl;
        //ctr
        start = high_resolution_clock::now();
        CTR_ED(test, key, counter);
        stop = high_resolution_clock::now();
        duration = duration_cast<milliseconds>(stop - start);
        cout <<"CTR: "<<  duration.count()<<"ms" << endl;
        test+=test;
        blockCount+=blockCount;
    }

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