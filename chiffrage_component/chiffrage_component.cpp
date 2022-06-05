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
#include "cryptopp/files.h"
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

	std::string encrypt(std::string message){
    		using namespace CryptoPP;
		std::string encryptedMessage;
    		try{
        		AutoSeededRandomPool prng;
			ECIES<ECP>::Decryptor decryptor;
			decryptor.AccessKey().Initialize(prng, ASN1::secp256k1());

        		//public key is a point consisting of "public key point x" and "public key point y"
        		//compressed public key also known as "public-point" formed using point-compression of public key


        		//since the key is in base-64 format use Base64Decoder
			ECIES<ECP>::Encryptor encryptor(decryptor);
			encryptor.AccessKey().AccessGroupParameters().SetPointCompression(true);
			std::string compressedPublicKeyPoint;
			encryptor.GetKey().Save(StringSink(compressedPublicKeyPoint).Ref());
        		std::string s3;
			StringSource ss3(compressedPublicKeyPoint, true, new HexEncoder(new StringSink(s3)));
			std::cout << "compressedPublicKeyPoint : " << s3 << std::endl;
			StringSource ss(compressedPublicKeyPoint, true, new CryptoPP::Base64Decoder);

        		//curve used is secp256k1
        		encryptor.AccessKey().AccessGroupParameters().Initialize(ASN1::secp256k1());

        		//get point on the used curve
        		const ECP::Point point = encryptor.GetKey().GetPublicElement();
			const Integer point_x = point.x;
			const Integer point_y = point.y;
			//ECP::Point point;
        		//encryptor.GetKey().GetGroupParameters().GetCurve().DecodePoint(point, ss, ss.MaxRetrievable());
        		std::cout << "X: " << std::hex << point_x << std::endl;
        		std::cout << "Y: " << std::hex << point_y << std::endl;

        		//set encryptor's public element
        		encryptor.AccessKey().SetPublicElement(point);

        		//check whether the encryptor's access key thus formed is valid or not
        		encryptor.AccessKey().ThrowIfInvalid(prng, 3);

        		// encrypted message
        		StringSource ss1(message, true, new PK_EncryptorFilter(prng, encryptor,new HexEncoder( new StringSink(encryptedMessage))));
			std::cout<<"encrypted msg: "<<encryptedMessage<<"  and its length: "<<encryptedMessage.length()<<std::endl;

			std::string decryptedMessage;
			bool valid = decryptor.AccessKey().Validate(prng, 3);
        		if(!valid){
           			decryptor.AccessKey().ThrowIfInvalid(prng, 3);
			}
        		std::cout << "Exponent is valid for P-256k1" << std::endl;
			StringSource ss2 (encryptedMessage, true, new PK_DecryptorFilter(prng, decryptor,new StringSink(decryptedMessage)));
        		std::cout <<"decrypted msg: "<< decryptedMessage<<"  and its length: "<<decryptedMessage.length() << std::endl;
		}
    		catch(const CryptoPP::Exception& ex){
        		std::cerr << ex.what() << std::endl;
    		}

    		return encryptedMessage;
	}
	//const void encrypt_decrypt(std::string plaintext){
		//using namespace CryptoPP;
		//ECIES<ECP>::PrivateKey privateKey;
		//ECIES<ECP>::PublicKey publicKey;
		//AutoSeededRandomPool rng;

		// Curve Key Generation
		//privateKey.Initialize( rng, ASN1::secp256k1());
		//privateKey.MakePublicKey( publicKey );

		// Encryptor and Decryptor
		//ECIES<ECP>::Encryptor encryptor( publicKey );
		//ECIES<ECP>::Decryptor decryptor( privateKey );

		// Message
		//std::string plainText = plaintext;
		//int plainTextLength = plainText.length();
		//std::string cipherText = plaintext;
		//int cipherTextLength = cipherText.length();
		// Encryption
		//encryptor.Encrypt( rng, reinterpret_cast<const byte*>(plainText.c_str()), plainTextLength, cipherText);

		// Decryption
		//DecodingResult result = decryptor.Decrypt( rng, cipherText, cipherTextLength, reinterpret_cast<byte*>(recoveredText));

		// Crypto++ Test
		//if( false == result.isValidCoding ) {
    		//throw std::runtime_error("Crypto++: decryption failed");
		//}
	//}

	void encrypt_decrypt2(){
		using namespace CryptoPP;
    		AutoSeededRandomPool prng;
   		std::string message= "Floryan est le realisateur du composant"; 
    		/////////////////////////////////////////////////
    		// Part one - generate keys
    		ECIES<ECP>::PrivateKey privateKey;
                ECIES<ECP>::PublicKey publicKey;

		
                // Curve Key Generation
                privateKey.Initialize( prng, ASN1::secp256k1());
                privateKey.MakePublicKey(publicKey);
		const std::string& DecryptorfilePublic = "ECIES_PublicKey.key";
		SavePublicKey(publicKey,DecryptorfilePublic);
                
		ECIES<ECP>::Encryptor e0;
		LoadPublicKey(e0.AccessPublicKey(),DecryptorfilePublic);
    		e0.GetPublicKey().ThrowIfInvalid(prng, 3);

                //ECIES<ECP>::Encryptor e0(publicKey);
                ECIES<ECP>::Decryptor d0(privateKey);
    		//ECIES<ECP>::Decryptor d0(prng, ASN1::secp256k1());
    		//PrintPrivateKey(d0.GetKey());

    		//ECIES<ECP>::Encryptor e0(d0);
    		//PrintPublicKey(e0.GetKey());
    		    		
		
		/////////////////////////////////////////////////
    		// Part two - encrypt/decrypt with e0/d0
    
    		std::string em0; // encrypted message
    		StringSource ss1 (message, true, new PK_EncryptorFilter(prng, e0, new StringSink(em0) ) );
		std::string em0Hex;
		StringSource ss3(em0, true, new HexEncoder(new StringSink(em0Hex)));
    		std::string dm0; // decrypted message
    		StringSource ss2 (em0, true, new PK_DecryptorFilter(prng, d0, new StringSink(dm0) ) );
   		
    		std::cout << "Encrypted Message : "<<std::hex<< em0 << std::endl;
		std::cout << "Encrypted Message (std::hex) : ";
                for (const auto &item : em0) {
                        std::cout << std::hex << int(item);
                } 
                std::cout<< std::endl;
		std::cout << "Encrypted Message (HexEncoder) : "<< em0Hex << std::endl;
    		std::cout << "Decrypted Message : "<< dm0 << std::endl;
	}

	void SavePrivateKey(const CryptoPP::PrivateKey& key, const std::string& file){
    		CryptoPP::FileSink sink(file.c_str());
    		key.Save(sink);
	}

	void SavePublicKey(const CryptoPP::PublicKey& key, const std::string& file){
    		CryptoPP::FileSink sink(file.c_str());
    		key.Save(sink);
	}

	void LoadPrivateKey(CryptoPP::PrivateKey& key, const std::string& file){
    		CryptoPP::FileSource source(file.c_str(), true);
    		key.Load(source);
	}

	void LoadPublicKey(CryptoPP::PublicKey& key, const std::string& file){
    		CryptoPP::FileSource source(file.c_str(), true);
    		key.Load(source);
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
		.def("encrypt_decrypt2", &Chiffrage::encrypt_decrypt2)
		.def("LoadPublicKey", &Chiffrage::LoadPublicKey)
		.def("LoadPrivateKey", &Chiffrage::LoadPrivateKey)
		.def("SavePublicKey", &Chiffrage::SavePublicKey)
		.def("SavePriavteKey", &Chiffrage::SavePrivateKey)
		//.def("PrintPrivateKey",&Chiffrage::PrintPrivateKey)
		//.def("PrintPublicKey", &Chiffrage::PrintPublicKey)
		//.def("encrypt_decrypt", &Chiffrage::encrypt_decrypt)
		.def("showBothKeys", &Chiffrage::showBothKeys);
}
