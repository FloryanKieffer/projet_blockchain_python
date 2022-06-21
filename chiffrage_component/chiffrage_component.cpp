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
    	public:
        	Chiffrage(){}
        	~Chiffrage(){} 

		
        const std::string &getPlaintext() const { 
		return plaintext;
	}

	const std::string &getEncryptedText() const {
		 return encryptedtext;; 
	}
	
	void encrypt_decrypt(std::string em){
		using namespace CryptoPP; //Utilisation de la librairie CryptoPP
    		AutoSeededRandomPool prng;
   		std::string message= em;
		
    		/////////////////////////////////////////////////
    		// Part one - generate keys
    		ECIES<ECP>::PrivateKey privateKey;
                ECIES<ECP>::PublicKey publicKey;

		
                // Curve Key Generation
                privateKey.Initialize( prng, ASN1::secp256k1());//Generation courbe ECIES
                privateKey.MakePublicKey(publicKey);//Generation cle publique
		const std::string& DecryptorfilePublic = "ECIES_PublicKey.key";//Chemin vers le fichier de stockage de la cle publique
		const std::string& DecryptorfilePrivate = "ECIES_PrivateKey.key";//Chemin vers le fichier de stockage de la cle prive
		SavePublicKey(publicKey,DecryptorfilePublic);//Sauvegarde cle publique
		SavePrivateKey(privateKey,DecryptorfilePrivate);//Sauvegarde clé privee
                
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
		
		/////////////////////////////////////////////////
    		// Part three - decrypt
		
                ECIES<ECP>::Decryptor d0(privateKey);
    		//ECIES<ECP>::Decryptor d0(prng, ASN1::secp256k1());
    		//PrintPrivateKey(d0.GetKey());
    		
    		std::string dm0; // decrypted message
    		StringSource ss2 (em0, true, new PK_DecryptorFilter(prng, d0, new StringSink(dm0) ) );
   		plaintext = dm0;
    		
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
	
	void PrintPrivateKey(const DL_PrivateKey_EC<ECP>& key, ostream& out){
		using namespace CryptoPP;
		// Group parameters
		const DL_GroupParameters_EC<ECP>& params = key.GetGroupParameters();
		// Base precomputation (for public key calculation from private key)
	        const DL_FixedBasePrecomputation<ECPPoint>& bpc = params.GetBasePrecomputation();
		// Public Key (just do the exponentiation)
		const ECPPoint point = bpc.Exponentiate(params.GetGroupPrecomputation(), key.GetPrivateExponent());

		out << "Modulus: " << std::hex << params.GetCurve().GetField().GetModulus() << endl;
		out << "Cofactor: " << std::hex << params.GetCofactor() << endl;

		out << "Coefficients" << endl;
		out << "  A: " << std::hex << params.GetCurve().GetA() << endl;
		out << "  B: " << std::hex << params.GetCurve().GetB() << endl;

		out << "Base Point" << endl;
		out << "  x: " << std::hex << params.GetSubgroupGenerator().x << endl;
		out << "  y: " << std::hex << params.GetSubgroupGenerator().y << endl;

		out << "Public Point" << endl;
		out << "  x: " << std::hex << point.x << endl;
		out << "  y: " << std::hex << point.y << endl;

		out << "Private Exponent (multiplicand): " << endl;
		out << "  " << std::hex << key.GetPrivateExponent() << endl;
	}

	void PrintPublicKey(const DL_PublicKey_EC<ECP>& key, ostream& out){
		using namespace CryptoPP;
	    	// Group parameters
	    	const DL_GroupParameters_EC<ECP>& params = key.GetGroupParameters();
	    	// Public key
	    	const ECPPoint& point = key.GetPublicElement();

		    out << "Modulus: " << std::hex << params.GetCurve().GetField().GetModulus() << endl;
		    out << "Cofactor: " << std::hex << params.GetCofactor() << endl;

		    out << "Coefficients" << endl;
		    out << "  A: " << std::hex << params.GetCurve().GetA() << endl;
		    out << "  B: " << std::hex << params.GetCurve().GetB() << endl;

		    out << "Base Point" << endl;
		    out << "  x: " << std::hex << params.GetSubgroupGenerator().x << endl;
		    out << "  y: " << std::hex << params.GetSubgroupGenerator().y << endl;

		    out << "Public Point" << endl;
		    out << "  x: " << std::hex << point.x << endl;
		    out << "  y: " << std::hex << point.y << endl;
	}

};
 
namespace py = pybind11;


PYBIND11_MODULE(chiffrage_component,greetings)
{
  	greetings.doc() = "chiffrage_component 1.0";
    	py::class_<Chiffrage>(greetings, "Chiffrage", py::dynamic_attr())
        	.def(py::init())
		.def("encrypt_decrypt", &Chiffrage::encrypt_decrypt)
		.def("LoadPublicKey", &Chiffrage::LoadPublicKey)
		.def("LoadPrivateKey", &Chiffrage::LoadPrivateKey)
		.def("SavePublicKey", &Chiffrage::SavePublicKey)
		.def("SavePriavteKey", &Chiffrage::SavePrivateKey)
		.def("PrintPublicKey", &Chiffrage::PrintPublicKey)
		.def("PrintPrivateKey", &Chiffrage::PrintPrivateKey);
}
