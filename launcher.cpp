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
#include <iostream>
#include <string>
#include <ctime>
#include <map>

#define CERTS_DIR "certs"
#define ROOT_KEY_FILE CERTS_DIR "/root_key.pem"
#define ROOT_CERT_FILE CERTS_DIR "/root_cert.pem"
#define CRL_FILE CERTS_DIR "/crl.pem"
#define CERT_DIR CERTS_DIR "/certs"

// Error handling macro
#define handle_error(msg) do { perror(msg); exit(1); } while (0)

using namespace std;

// Get current time
time_t get_current_time() {
    time_t now = time(0);
    return now;
}

// Self-signed root certificate creation
void generate_root_certificate(int days_valid = 3650) {
    RSA *rsa = RSA_new();
    BIGNUM *bn = BN_new();
    BN_set_word(bn, RSA_F4);
    if (RSA_generate_key_ex(rsa, 2048, bn, NULL) != 1) handle_error("RSA key generation failed");

    EVP_PKEY *pkey = EVP_PKEY_new();
    EVP_PKEY_assign_RSA(pkey, rsa);

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
    BN_free(bn);

    cout << "Root certificate generated successfully." << endl;
}

// Generate a certificate signed by the root certificate
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
    RSA *rsa = RSA_new();
    BIGNUM *bn = BN_new();
    BN_set_word(bn, RSA_F4);
    if (RSA_generate_key_ex(rsa, 2048, bn, NULL) != 1) handle_error("RSA key generation failed");

    EVP_PKEY *pkey = EVP_PKEY_new();
    EVP_PKEY_assign_RSA(pkey, rsa);

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
    BN_free(bn);

    cout << "Certificate for " << domain << " generated and signed by root." << endl;
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


// Function to check certificate expiration and renew if necessary
void renew_certificate_if_needed(const string &domain, const string &issuer_cert_file, const string &issuer_key_file) {
    // Load the existing certificate to check its expiration
    string cert_file_name = CERT_DIR "/" + domain + "_cert.pem";
    FILE *cert_file = fopen(cert_file_name.c_str(), "rb");
    X509 *existing_cert = PEM_read_X509(cert_file, NULL, NULL, NULL);
    fclose(cert_file);
    if (!existing_cert) handle_error("Failed to load existing certificate");

    // Check expiration date
    ASN1_TIME *not_after = X509_get_notAfter(existing_cert);
    time_t current_time = get_current_time();
    if (ASN1_TIME_diff(NULL, NULL, not_after, NULL) < 0) {
        // If expired, renew the certificate
        generate_certificate(domain, issuer_cert_file, issuer_key_file);
    }

    X509_free(existing_cert);
}

int main() {

    system("mkdir -p certs/certs");
    generate_root_certificate();

    // Generate a certificate for a domain (example: "example.com")
    generate_certificate("example.com", ROOT_CERT_FILE, ROOT_KEY_FILE);

    // Create CRL and revoke a certificate (for testing purposes)
    create_crl(CERT_DIR "/example.com_cert.pem");

    // Check if the certificate is expired and renew if necessary
    renew_certificate_if_needed("example.com", ROOT_CERT_FILE, ROOT_KEY_FILE);

    return 0;
}
