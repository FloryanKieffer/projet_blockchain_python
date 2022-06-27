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


class Chiffrage
{
	private:
		std::string plaintext;
		std::string encryptedtext;
		std::string encryptedtextBin;
    	public:
        	Chiffrage(){}
        	~Chiffrage(){} 

		
        const std::string &getPlaintext() const { 
		return plaintext;
	}

	const std::string getEncryptedText() const {
		 return encryptedtext;; 
	}

	const std::string getEncryptedTextBin()const{
		return encryptedtextBin;
	}
	
	void encrypt(std::string em, const std::string& DecryptorfilePublic){
		using namespace CryptoPP;
		ECIES <ECP> ::Encryptor e0;
		AutoSeededRandomPool prng;
		
		plaintext = em;
            	LoadPublicKey(e0.AccessPublicKey(), DecryptorfilePublic);
            	e0.GetPublicKey().ThrowIfInvalid(prng, 3);
		std::cout <<"#####################################PubicKey#####################################"<<std::endl;
		ECIES<ECP>::PublicKey pubKey;
		LoadPublicKey(pubKey, DecryptorfilePublic);
		PrintPublicKey(pubKey);
		std::cout <<"##################################################################################"<<std::endl;
		std::cout <<"#################################Encrypted Message################################"<<std::endl;
            	std::string em0;
		StringSource ss1(plaintext, true, new PK_EncryptorFilter(prng, e0, new StringSink(em0)));
                std::string em0Hex;
                StringSource ss3(em0, true, new HexEncoder(new StringSink(em0Hex)));
                encryptedtext = em0Hex;
		encryptedtextBin = em0;
            	std::cout << "Plain text Message : " << plaintext << std::endl;
            	
           	std::cout << "Encrypted Message (HexEncoder) : " << em0Hex << std::endl;
		std::cout <<"##################################################################################"<<std::endl;
	}
	
	/*void encrypt_decrypt(std::string em){
		using namespace CryptoPP; //Utilisation de la librairie CryptoPP
    		AutoSeededRandomPool prng;
   		std::string message= em;
		
    		/////////////////////////////////////////////////
    		// Part one - generate keys
    		ECIES<ECP>::PrivateKey privateKey;
                ECIES<ECP>::PublicKey publicKey;

		
                // Curve Key Generation
                privateKey.Initialize( prng, ASN1::secp256k1());//Initialisation private key avec courbe ECIES
                privateKey.MakePublicKey(publicKey);//Generation cle publique
		const std::string& DecryptorfilePublic = "ECIES_PublicKey.key";//Chemin vers le fichier de stockage de la cle publique
		const std::string& DecryptorfilePrivate = "ECIES_PrivateKey.key";//Chemin vers le fichier de stockage de la cle prive
		
		SavePublicKey(publicKey,DecryptorfilePublic);//Sauvegarde cle publique
		SavePrivateKey(privateKey,DecryptorfilePrivate);//Sauvegarde clé privee
                
		PrintPublicKey(publicKey);
		PrintPrivateKey(privateKey);
		
		/////////////////////////////////////////////////
    		// Part two - encrypt
		
		ECIES<ECP>::Encryptor e0;
		LoadPublicKey(e0.AccessPublicKey(),DecryptorfilePublic);
    		e0.GetPublicKey().ThrowIfInvalid(prng, 3);
		//ECIES<ECP>::Encryptor e0(publicKey);
		//ECIES<ECP>::Encryptor e0(d0);
    		//PrintPublicKey(e0.GetKey());
		std::string em0; // encrypted message
    		StringSource ss1 (message, true, new PK_EncryptorFilter(prng, e0, new StringSink(em0) ) );
		encryptedtext = em0;
		std::string em0Hex;
		StringSource ss3(em0, true, new HexEncoder(new StringSink(em0Hex)));
		
		std::cout << "Encrypted Message : "<<std::hex<< em0 << std::endl;
		std::cout << "Encrypted Message (std::hex) : ";
                for (const auto &item : em0) {
                        std::cout << std::hex << int(item);
                } 
                std::cout<< std::endl;
		std::cout << "Encrypted Message (HexEncoder) : "<< em0Hex << std::endl;
		std::string hexpubkey;

		// Hex Encoder
		HexEncoder encoder;

		// Public Key
		encoder.Attach( new StringSink(hexpubkey) );
		e0.GetPublicKey().Save( encoder );
		std::cout << "PublicKey" << hexpubkey << std::endl;
		/////////////////////////////////////////////////
    		// Part three - decrypt
		
                ECIES<ECP>::Decryptor d0(privateKey);
    		//ECIES<ECP>::Decryptor d0(prng, ASN1::secp256k1());
    		//PrintPrivateKey(d0.GetKey());
    		
    		std::string dm0; // decrypted message
    		StringSource ss2 (em0, true, new PK_DecryptorFilter(prng, d0, new StringSink(dm0) ) );
   		plaintext = dm0;
    		
    		std::cout << "Decrypted Message : "<< dm0 << std::endl;
	}*/

	void SavePublicKey(const CryptoPP::PublicKey& key, const std::string& file){
    		CryptoPP::FileSink sink(file.c_str());
    		key.Save(sink);
	}

	void LoadPublicKey(CryptoPP::PublicKey& key, const std::string& file){
    		CryptoPP::FileSource source(file.c_str(), true);
    		key.Load(source);
	}
	
	void PrintPublicKey(const CryptoPP::DL_PublicKey_EC<CryptoPP::ECP>& key)
	{
    		using namespace CryptoPP;
		// Group parameters
    		const DL_GroupParameters_EC<ECP>& params = key.GetGroupParameters();
    		// Public key
    		const ECPPoint& point = key.GetPublicElement();
    
   		std::cout << "Modulus: " << std::hex << params.GetCurve().GetField().GetModulus() << std::endl;
    		std::cout << "Cofactor: " << std::hex << params.GetCofactor() << std::endl;
    
    		std::cout << "Coefficients" << std::endl;
    		std::cout << "  A: " << std::hex << params.GetCurve().GetA() << std::endl;
    		std::cout << "  B: " << std::hex << params.GetCurve().GetB() << std::endl;
    
    		std::cout << "Base Point" << std::endl;
    		std::cout << "  x: " << std::hex << params.GetSubgroupGenerator().x << std::endl;
    		std::cout << "  y: " << std::hex << params.GetSubgroupGenerator().y << std::endl;
    
   		std::cout << "Public Point" << std::endl;
    		std::cout << "  x: " << std::hex << point.x << std::endl;
    		std::cout << "  y: " << std::hex << point.y << std::endl;	
	}
};
 
namespace py = pybind11;


PYBIND11_MODULE(chiffrage_component,greetings)
{
  	greetings.doc() = "chiffrage_component 1.0";
    	py::class_<Chiffrage>(greetings, "Chiffrage", py::dynamic_attr())
        	.def(py::init())
		.def("getPlaintext", &Chiffrage::getPlaintext)
		.def("getEncryptedText", &Chiffrage::getEncryptedText)
		.def("getEncryptedTextBin", &Chiffrage::getEncryptedTextBin)
		.def("encrypt", &Chiffrage::encrypt)
		.def("LoadPublicKey", &Chiffrage::LoadPublicKey)
		.def("SavePublicKey", &Chiffrage::SavePublicKey)
		.def("PrintPublicKey", &Chiffrage::PrintPublicKey);
}
