#include <pybind11/pybind11.h>
#include "micro-ecc/uECC.h"
#include <iostream>
uint8_t hexchr2bin(const char hex)
{
	uint8_t result;

	if (hex >= '0' && hex <= '9') {
		result = hex - '0';
	} else if (hex >= 'A' && hex <= 'F') {
		result = hex - 'A' + 10;
	} else if (hex >= 'a' && hex <= 'f') {
		result = hex - 'a' + 10;
	} else {
		return 0;
	}
	return result;
}



void hexStringToBin(uint8_t *out,const char * hexPrivate) {
    for (int i=0; i<32; i++){
	out[i] = hexchr2bin(hexPrivate[2*i])<<4 | hexchr2bin(hexPrivate[2*i+1]);
    }
}


char *binToHexString(char *out,const unsigned char *bin, size_t len)
{
    size_t  i;

    if (bin == NULL || len == 0)
	return NULL;

    for (i=0; i<len; i++) {

	out[i*2]   = "0123456789abcdef"[bin[i] >> 4];
	out[i*2+1] = "0123456789abcdef"[bin[i] & 0x0F];
    }
    out[len*2] = '\0';

    return out;
}

class Chiffrage
{
	private:
		std::string PrivateKey;
		std::string PublicKey;
    	public:
        	Chiffrage(){}
        	~Chiffrage(){} 

        void initialize(std::string &nb) { 
		PrivateKey=nb;
		uint8_t binaryPrivate[32];
		hexStringToBin(binaryPrivate,PrivateKey.c_str());
		const int publicKeySize=uECC_curve_public_key_size(uECC_secp256k1());
		uint8_t *varIntPublicKey = new uint8_t[publicKeySize];
		uECC_compute_public_key(binaryPrivate,varIntPublicKey,uECC_secp256k1());
		char hexPublicKey[128];
		binToHexString(hexPublicKey,varIntPublicKey,64);
		PublicKey=std::string(hexPublicKey,128);
	}
		
        const std::string &getPrivateKey() const { 
		return PrivateKey;
	}

	const std::string &getPublicKey() const {
		 return PublicKey; 
	}

	void showBothKeys(){
		std::cout<<"PrivateKey : "<<getPrivateKey()<<"\n";
       		std::cout<<"PublicKey : "<<getPublicKey()<<"\n";
	}
};
 
namespace py = pybind11;


PYBIND11_MODULE(chiffrage_component,greetings)
{
  	greetings.doc() = "chiffrage_cle 1.0";
    	py::class_<Chiffrage>(greetings, "Chiffrage", py::dynamic_attr())
        	.def(py::init())
        	.def("initialize", &Cle::initialize)
        	.def("getPrivateKey", &Cle::getPrivateKey)
        	.def("getPublicKey", &Cle::getPublicKey)
		.def("showBothKeys", &Cle::showBothKeys);
}
