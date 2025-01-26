#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>
#include <openssl/rand.h>
#include <openssl/ocsp.h>
#include "../include/DES.h"
#include <iostream>
#include <string>
#include <ctime>
#include <map>

#define CERTS_DIR "../certs"
#define ROOT_KEY_FILE CERTS_DIR "/root_key.pem"
#define ROOT_CERT_FILE CERTS_DIR "/root_cert.pem"
#define CRL_FILE CERTS_DIR "/crl.pem"
#define CERT_DIR CERTS_DIR "/certs"


// Macro for error handling
#define handle_error(msg) do { perror(msg); exit(1); } while (0)

using namespace std;

time_t get_current_time() {
    time_t now = time(0);
    return now;
}

// Self-signed root certificate creation
void generate_root_certificate(int days_valid = 3650) {
    EVP_PKEY *pkey = EVP_PKEY_new();
EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
if (!ctx || EVP_PKEY_keygen_init(ctx) <= 0 || EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0) {
    handle_error("Failed to initialize RSA key generation");
}
if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
    handle_error("RSA key generation failed");
}
EVP_PKEY_CTX_free(ctx);

    X509 *x509 = X509_new();
    X509_set_version(x509, 2);  // X509 version 3
    ASN1_INTEGER_set(X509_get_serialNumber(x509), 1);  // Serial number is set to 1 for root
    X509_gmtime_adj(X509_get_notBefore(x509), 0);  // Valid from now
    X509_gmtime_adj(X509_get_notAfter(x509), days_valid * 24 * 60 * 60);  // Expiration date

    X509_set_pubkey(x509, pkey);

    X509_NAME *name = X509_get_subject_name(x509);
    X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, (unsigned char *)"RO", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, (unsigned char *)"MyCA", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char *)"MyRootCA", -1, -1, 0);
    X509_set_issuer_name(x509, name);

    if (X509_sign(x509, pkey, EVP_sha256()) == 0) handle_error("Error signing root certificate");

    FILE *key_file = fopen(ROOT_KEY_FILE, "wb");
    if (!key_file) handle_error("Unable to open root key file for writing");
    PEM_write_PrivateKey(key_file, pkey, NULL, NULL, 0, NULL, NULL);
    fclose(key_file);

    FILE *cert_file = fopen(ROOT_CERT_FILE, "wb");
    if (!cert_file) handle_error("Unable to open root cert file for writing");
    PEM_write_X509(cert_file, x509);
    fclose(cert_file);

    X509_free(x509);
    EVP_PKEY_free(pkey);

    cout << "Root certificate generated successfully." << endl;
}

// Function to generate a certificate signed by the root certificate
void generate_certificate(const string &domain, const string &issuer_cert_file, const string &issuer_key_file, int days_valid = 365) {
    // Load issuer private key
    FILE *key_file = fopen(issuer_key_file.c_str(), "rb");
    if (!key_file) handle_error("Failed to load issuer private key");
    EVP_PKEY *issuer_pkey = PEM_read_PrivateKey(key_file, NULL, NULL, NULL);
    fclose(key_file);
    if (!issuer_pkey) handle_error("Failed to load issuer private key");

    // Load issuer certificate
    FILE *cert_file = fopen(issuer_cert_file.c_str(), "rb");
    if (!cert_file) handle_error("Failed to load issuer certificate");
    X509 *issuer_cert = PEM_read_X509(cert_file, NULL, NULL, NULL);
    fclose(cert_file);
    if (!issuer_cert) handle_error("Failed to load issuer certificate");

    // Generate RSA key for the new certificate
    EVP_PKEY *pkey = EVP_PKEY_new();
EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
if (!ctx || EVP_PKEY_keygen_init(ctx) <= 0 || EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0) {
    handle_error("Failed to initialize RSA key generation");
}
if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
    handle_error("RSA key generation failed");
}
EVP_PKEY_CTX_free(ctx);


    // Create the X509 certificate
    X509 *x509 = X509_new();
    X509_set_version(x509, 2);
    ASN1_INTEGER_set(X509_get_serialNumber(x509), 1);  // Serial number for this certificate
    X509_gmtime_adj(X509_get_notBefore(x509), 0);  // Valid from now
    X509_gmtime_adj(X509_get_notAfter(x509), days_valid * 24 * 60 * 60);  // Expiration date

    X509_set_pubkey(x509, pkey);

    // Set the subject name (CN should be the domain)
    X509_NAME *name = X509_get_subject_name(x509);
    X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, (unsigned char *)"RO", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, (unsigned char *)"MyCA", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char *)domain.c_str(), -1, -1, 0);
    X509_set_issuer_name(x509, X509_get_subject_name(issuer_cert));

    // Sign the certificate with the issuer's private key
    if (X509_sign(x509, issuer_pkey, EVP_sha256()) == 0) handle_error("Error signing certificate");

    // Save the signed certificate to file
    string cert_file_name = CERT_DIR "/" + domain + "_cert.pem";
    FILE *cert_out = fopen(cert_file_name.c_str(), "wb");
    if (!cert_out) handle_error("Unable to open certificate file for writing");
    PEM_write_X509(cert_out, x509);
    fclose(cert_out);

    // Save the private key to file
    string key_file_name = CERT_DIR "/" + domain + "_key.pem";
    FILE *key_out = fopen(key_file_name.c_str(), "wb");
    if (!key_out) handle_error("Unable to open key file for writing");
    PEM_write_PrivateKey(key_out, pkey, NULL, NULL, 0, NULL, NULL);
    fclose(key_out);

    // Clean up
    X509_free(x509);
    EVP_PKEY_free(pkey);
    EVP_PKEY_free(issuer_pkey);
    X509_free(issuer_cert);

    cout << "Certificate for " << domain << " generated and signed by root." << endl;
}

void generate_user_certificate(const string &username, const string &issuer_cert_file, const string &issuer_key_file, int days_valid = 365) {
    string key_file = CERT_DIR "/" + username + "_key.pem";
    string cert_file = CERT_DIR "/" + username + "_cert.pem";
    generate_certificate(username, issuer_cert_file, issuer_key_file, days_valid);

    cout << "Certificat generat pentru " << username << " la: " << cert_file << endl;
}


// Function to create a CRL (Certificate Revocation List) and add a revoked certificate
void create_crl(const string &revoked_cert_file_path) {
    // Create a new CRL object
    X509_CRL *crl = X509_CRL_new();
    if (!crl) handle_error("Failed to create CRL");

    // Set the CRL version
    X509_CRL_set_version(crl, 1);

    // Set the CRL issuer (should be the root certificate subject)
    FILE *root_cert_file = fopen(ROOT_CERT_FILE, "rb");
    X509 *root_cert = PEM_read_X509(root_cert_file, NULL, NULL, NULL);
    fclose(root_cert_file);
    X509_NAME *issuer_name = X509_get_subject_name(root_cert);
    X509_CRL_set_issuer_name(crl, issuer_name);

    // Set the last update time
    ASN1_TIME *last_update = ASN1_TIME_new();
    ASN1_TIME_set(last_update, get_current_time());
    X509_CRL_set_lastUpdate(crl, last_update);

    // Set the next update time
    ASN1_TIME *next_update = ASN1_TIME_new();
    ASN1_TIME_set(next_update, get_current_time() + 86400 * 365);  // 1 year from now
    X509_CRL_set_nextUpdate(crl, next_update);

    // Add the revoked certificate to the CRL
    FILE *revoked_cert_file = fopen(revoked_cert_file_path.c_str(), "rb"); // Renamed the local variable here
    X509 *revoked_cert = PEM_read_X509(revoked_cert_file, NULL, NULL, NULL);
    fclose(revoked_cert_file);
    X509_REVOKED *revoked_entry = X509_REVOKED_new();
    ASN1_TIME *revoked_time = ASN1_TIME_new();
    ASN1_TIME_set(revoked_time, get_current_time());  // Revocation time

    X509_REVOKED_set_serialNumber(revoked_entry, X509_get_serialNumber(revoked_cert));
    X509_REVOKED_set_revocationDate(revoked_entry, revoked_time);
    X509_CRL_add0_revoked(crl, revoked_entry);

    // Save the CRL to file
    FILE *crl_out = fopen(CRL_FILE, "wb");
    if (!crl_out) handle_error("Unable to open CRL file for writing");
    PEM_write_X509_CRL(crl_out, crl);
    fclose(crl_out);

    ASN1_TIME_free(last_update);
    ASN1_TIME_free(next_update);
    ASN1_TIME_free(revoked_time);
    X509_CRL_free(crl);
    X509_free(revoked_cert);

    cout << "CRL created and certificate revoked." << endl;
}

vector<uint8_t> encrypt_with_public_key(const vector<uint8_t> &symmetric_key, EVP_PKEY *pubkey) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pubkey, NULL);
    if (!ctx || EVP_PKEY_encrypt_init(ctx) <= 0) handle_error("Failed to initialize encryption context");

    size_t encrypted_len;
    if (EVP_PKEY_encrypt(ctx, NULL, &encrypted_len, symmetric_key.data(), symmetric_key.size()) <= 0) handle_error("Failed to determine encrypted length");

    vector<uint8_t> encrypted_key(encrypted_len);
    if (EVP_PKEY_encrypt(ctx, encrypted_key.data(), &encrypted_len, symmetric_key.data(), symmetric_key.size()) <= 0) handle_error("Failed to encrypt symmetric key");

    EVP_PKEY_CTX_free(ctx);
    return encrypted_key;
}

bool validate_certificate(const string &cert_file, EVP_PKEY *ca_pubkey) {
    FILE *cert_fp = fopen(cert_file.c_str(), "rb");
    if (!cert_fp) {
        cerr << "Error: Unable to open certificate file " << cert_file << endl;
        return false;
    }

    X509 *cert = PEM_read_X509(cert_fp, NULL, NULL, NULL);
    fclose(cert_fp);
    if (!cert) {
        cerr << "Error: Failed to read certificate from file " << cert_file << endl;
        return false;
    }

    int valid = X509_verify(cert, ca_pubkey);
    if (valid != 1) {
        unsigned long err = ERR_get_error();
        char err_msg[256];
        ERR_error_string_n(err, err_msg, sizeof(err_msg));
        cerr << "Error: Certificate validation failed. OpenSSL error: " << err_msg << endl;

        cout << "Certificate Subject: "
             << X509_NAME_oneline(X509_get_subject_name(cert), NULL, 0) << endl;
        cout << "Certificate Issuer: "
             << X509_NAME_oneline(X509_get_issuer_name(cert), NULL, 0) << endl;
    }

    X509_free(cert);
    return valid == 1;
}


vector<uint8_t> decrypt_with_private_key(const vector<uint8_t> &encrypted_key, EVP_PKEY *privkey) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(privkey, NULL);
    if (!ctx) handle_error("Failed to create EVP_PKEY_CTX");

    if (EVP_PKEY_decrypt_init(ctx) <= 0) handle_error("Failed to initialize decryption context");

    size_t decrypted_len;
    if (EVP_PKEY_decrypt(ctx, NULL, &decrypted_len, encrypted_key.data(), encrypted_key.size()) <= 0) {
        unsigned long err = ERR_get_error();
        char err_msg[256];
        ERR_error_string_n(err, err_msg, sizeof(err_msg));
        cerr << "Error determining decrypted length: " << err_msg << endl;
        EVP_PKEY_CTX_free(ctx);
        return {};
    }

    vector<uint8_t> decrypted_key(decrypted_len);
    if (EVP_PKEY_decrypt(ctx, decrypted_key.data(), &decrypted_len, encrypted_key.data(), encrypted_key.size()) <= 0) {
        unsigned long err = ERR_get_error();
        char err_msg[256];
        ERR_error_string_n(err, err_msg, sizeof(err_msg));
        cerr << "Decryption failed: " << err_msg << endl;
        EVP_PKEY_CTX_free(ctx);
        return {};
    }

    decrypted_key.resize(decrypted_len);
    EVP_PKEY_CTX_free(ctx);
    return decrypted_key;
}


// Function to check certificate expiration and renew if necessary
void renew_certificate_if_needed(const string &domain, const string &issuer_cert_file, const string &issuer_key_file) {
    // Load the existing certificate to check its expiration
    string cert_file_name = CERT_DIR "/" + domain + "_cert.pem";
    FILE *cert_file = fopen(cert_file_name.c_str(), "rb");
    X509 *existing_cert = PEM_read_X509(cert_file, NULL, NULL, NULL);
    fclose(cert_file);
    if (!existing_cert) handle_error("Failed to load existing certificate");

    ASN1_TIME *not_after = X509_get_notAfter(existing_cert);
    time_t current_time = get_current_time();
    if (ASN1_TIME_diff(NULL, NULL, not_after, NULL) < 0) {
        generate_certificate(domain, issuer_cert_file, issuer_key_file);
    }

    X509_free(existing_cert);
}

int main() {
    // Here we check if we have Windows or another operating system to make directories
#ifdef _WIN32
    system("if not exist ..\\certs mkdir ..\\certs");
    system("if not exist ..\\certs\\certs mkdir ..\\certs\\certs");
#else
    system("mkdir -p ../certs/certs");
#endif

    // Generating the certificates for both users
    generate_root_certificate();
    generate_user_certificate("UserA", ROOT_CERT_FILE, ROOT_KEY_FILE);
    generate_user_certificate("UserB", ROOT_CERT_FILE, ROOT_KEY_FILE);

    // Transfer of the certificate from user A to user B
    FILE *fp_B = fopen(CERT_DIR "/UserB_cert.pem", "r");
    if (!fp_B) {
        cerr << "Error: Could not open UserB certificate at " << CERT_DIR "/UserB_cert.pem" << endl;
        return 1;
    }
    X509 *cert_B = PEM_read_X509(fp_B, NULL, NULL, NULL);
    fclose(fp_B);
    if (!cert_B) {
        cerr << "Error: Failed to read UserB certificate." << endl;
        return 1;
    }
    EVP_PKEY *pubkey_B = X509_get_pubkey(cert_B);
    if (!pubkey_B) {
        cerr << "Error: Could not extract public key from UserB certificate." << endl;
        return 1;
    }

    BIO *out = BIO_new_fp(stdout, BIO_NOCLOSE);
    cout << "UserB certificate details:" << endl;
    X509_print(out, cert_B);
    BIO_free(out);

    // User A encrypts the simetric key
    vector<uint8_t> symmetric_key = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
    vector<uint8_t> encrypted_key = encrypt_with_public_key(symmetric_key, pubkey_B);

    // Here we validate the User's B certificate
    FILE *ca_fp = fopen(ROOT_CERT_FILE, "r");
    if (!ca_fp) {
        cerr << "Error: Could not open root certificate at " << ROOT_CERT_FILE << endl;
        return 1;
    }
    X509 *root_cert = PEM_read_X509(ca_fp, NULL, NULL, NULL);
    fclose(ca_fp);
    if (!root_cert) {
        cerr << "Error: Failed to read root certificate." << endl;
        return 1;
    }
    EVP_PKEY *ca_pubkey = X509_get_pubkey(root_cert);
    if (!ca_pubkey) {
        cerr << "Error: Could not extract public key from root certificate." << endl;
        return 1;
    }

    // ROOT CERTIFICATE DETAILS
    cout << "Root certificate details:" << endl;
    BIO *out_root = BIO_new_fp(stdout, BIO_NOCLOSE);
    X509_print(out_root, root_cert);
    BIO_free(out_root);

    // PUBLIC KEY DETAILS
    cout << "Public key type: " << EVP_PKEY_base_id(ca_pubkey) << endl;
    if (EVP_PKEY_base_id(ca_pubkey) == EVP_PKEY_RSA) {
        cout << "Public key is RSA." << endl;
    } else {
        cout << "Unsupported public key type." << endl;
    }

    int valid = X509_verify(cert_B, ca_pubkey);
    if (valid != 1) {
        unsigned long err = ERR_get_error();
        char err_msg[256];
        ERR_error_string_n(err, err_msg, sizeof(err_msg));
        cerr << "X509_verify failed: " << err_msg << endl;
        return 1;
    }

    // Decrypting the simetric key by User B
    FILE *fp_priv_B = fopen(CERT_DIR "/UserB_key.pem", "r");
    if (!fp_priv_B) {
        cerr << "Error: Could not open UserB private key at " << CERT_DIR "/UserB_key.pem" << endl;
        return 1;
    }
    EVP_PKEY *privkey_B = PEM_read_PrivateKey(fp_priv_B, NULL, NULL, NULL);
    fclose(fp_priv_B);
    vector<uint8_t> decrypted_key = decrypt_with_private_key(encrypted_key, privkey_B);

    // Here we check if the keys match 
    if (symmetric_key != decrypted_key) {
        cout << "Error decrypting symmetric key" << endl;
        return 1;
    }
    cout << "The symmetric key was successfully transmitted and decrypted" << endl;

    // Encryption/Decryption using the algoritm from project 1

    DES des;
    string text = "ana are mere si";
    string key(reinterpret_cast<char*>(decrypted_key.data()), decrypted_key.size());

    string encryptedText = des.encryption(text, key, static_cast<uint8_t>(80));
    cout << "enryption (hex): " << encryptedText << endl;

    string decryptedText = des.decryption(encryptedText, key, static_cast<uint8_t>(80));
    cout << "decryption: " << decryptedText << endl;

    return 0;
}
