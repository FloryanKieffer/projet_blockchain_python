#include <pybind11/pybind11.h>
#include "micro-ecc/uECC.h"
#include "cryptopp/eccrypto.h"
#include "cryptopp/base64.h"
#include "cryptopp/filters.h"
#include "cryptopp/rsa.h"
#include "cryptopp/cryptlib.h"
#include "cryptopp/poly1305.h"
#include "cryptopp/osrng.h"
#include "cryptopp/aes.h"
#include "cryptopp/hex.h"
#include "cryptopp/integer.h"
#include "cryptopp/oids.h"
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
		std::string plaintext;
		std::string encryptedtext;
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

	std::string encrypt(std::string message ,  std::string  compressedPublicKeyPoint){
    		using namespace CryptoPP;
		std::string encryptedMessage;
    		try{
        		AutoSeededRandomPool prng;

        		//public key is a point consisting of "public key point x" and "public key point y"
        		//compressed public key also known as "public-point" formed using point-compression of public key


        		//since the key is in base-64 format use Base64Decoder
        		StringSource ss(compressedPublicKeyPoint, true, new CryptoPP::Base64Decoder);
     			ECIES<ECP>::Encryptor encryptor;

        		//curve used is secp256k1
        		encryptor.AccessKey().AccessGroupParameters().Initialize(ASN1::secp256k1());

        		//get point on the used curve
        		ECP::Point point;
        		encryptor.GetKey().GetGroupParameters().GetCurve().DecodePoint(point, ss, ss.MaxRetrievable());
        		std::cout << "X: " << std::hex << point.x << std::endl;
        		std::cout << "Y: " << std::hex << point.y << std::endl;

        		//set encryptor's public element
        		encryptor.AccessKey().SetPublicElement(point);

        		//check whether the encryptor's access key thus formed is valid or not
        		encryptor.AccessKey().ThrowIfInvalid(prng, 3);

        		// encrypted message
        		StringSource ss1(message, true, new PK_EncryptorFilter(prng, encryptor, new StringSink(encryptedMessage) ) );
        		std::cout<<"encrypted msg: "<<encryptedMessage<<"  and its length: "<<encryptedMessage.length()<<std::endl;
    		}
    		catch(const CryptoPP::Exception& ex){
        		std::cerr << ex.what() << std::endl;
    		}

    		return encryptedMessage;
	}
};
 
namespace py = pybind11;


PYBIND11_MODULE(chiffrage_component,greetings)
{
  	greetings.doc() = "chiffrage_component 1.0";
    	py::class_<Chiffrage>(greetings, "Chiffrage", py::dynamic_attr())
        	.def(py::init())
        	.def("initialize", &Chiffrage::initialize)
        	.def("getPrivateKey", &Chiffrage::getPrivateKey)
        	.def("getPublicKey", &Chiffrage::getPublicKey)
		.def("encrypt", &Chiffrage::encrypt)
		.def("showBothKeys", &Chiffrage::showBothKeys);
}
