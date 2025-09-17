// Implementation of Random number generation using a subset of digits and alphabets
#include <iostream>
#include <ctime>
#include <cstdlib>

using namespace std;

string randomkeygenerator(int keylen){
    
    string arr = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
    
    string result ="";
    
    for(int i=0;i<keylen;i++){
        int idx = rand()% arr.length() ;
        
        result += arr[idx];
        
    
    }
    
    return result;    

    
}

int main(){

    srand(time(0));
    int keylen =0;
    cout<<"Enter the key length : ";
    cin>>keylen;

    cout<<"Random Generated key is : "<<randomkeygenerator(keylen)<<endl;
    
    

    return 0;
}
