/*
 * This file is open source software, licensed to you under the terms
 * of the Apache License, Version 2.0 (the "License").  See the NOTICE file
 * distributed with this work for additional information regarding copyright
 * ownership.  You may not use this file except in compliance with the License.
 *
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
/*
 * Copyright 2015 Cloudius Systems
 */
#include <cmath>
#include <ranges>

#include <fcntl.h>
#include <sys/sendfile.h>

#include <openssl/pem.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/engine.h>
#include <openssl/pkcs12.h>
#include <openssl/provider.h>

#include <seastar/core/shared_ptr.hh>
#include <seastar/core/reactor.hh>
#include <seastar/core/app-template.hh>
#include <seastar/core/sleep.hh>
#include <seastar/core/loop.hh>
#include <seastar/net/byteorder.hh>
#include <seastar/net/dns.hh>
#include "tls_echo_server.hh"
#include "rsa.h"

using namespace seastar;
namespace bpo = boost::program_options;

struct NsTunnelFrameHeader
{
    uint16_t    m_controlVersion; //!< contains control and version
    uint16_t    m_type; //!< type
    uint32_t    m_flagsLength; //!< contain flags and length
};

struct NsTunnelDataTLVHeader
{
    uint16_t m_type{0};    //!< type
    uint16_t m_length{0};  //!< length
};

#define NS_FRAME_DATA(frame) (frame + sizeof(NsTunnelFrameHeader))

#define NS_TUNNEL_CONTROL_MASK 0x8000
#define NS_TUNNEL_VERSION_MASK 0x7fff

enum ns_tunnel_frame_type_t {
    NS_FRAME_TYPE_DATA = 0x0000,

    // control frame
    NS_FRAME_TYPE_PING = 0x0001,
    NS_FRAME_TYPE_PING_REPLY = 0x0002,
    NS_FRAME_TYPE_SYN_TUNNEL = 0x0003,
    NS_FRAME_TYPE_SYN_TUNNEL_AUTH_REQUIRED = 0x0004,
    NS_FRAME_TYPE_SYN_TUNNEL_AUTH_RESPONSE = 0x0005,
    NS_FRAME_TYPE_SYN_TUNNEL_REPLY = 0x0006,
    NS_FRAME_TYPE_UPDATE_PROPERTY = 0x0007,
    NS_FRAME_TYPE_UPDATE_PROPERTY_RESPONSE = 0x0008,
    NS_FRAME_TYPE_TLS_KEY = 0x0009,

    NS_FRAME_TYPE_FWD_AUTH = 0x1000,  //!< message used for forwarder authentication

    // set this to the last control frame type
    NS_FRAME_TYPE_CONTROL_LAST = NS_FRAME_TYPE_FWD_AUTH,
};

// Data types
// For the definition, we could refer to the 'Data TLV' in nsFrame.h.
// https://github.com/netSkope/client/blob/develop/lib/nsFrame/nsFrame.h
//
enum ns_tunnel_data_type_t {
    NS_DATA_TYPE_DEST_HOST = 0x0001,
    NS_DATA_TYPE_AUTH_NONCE = 0x0002,
    NS_DATA_TYPE_AUTH_SIGNED_NONCE = 0x0003,
    NS_DATA_TYPE_AUTH_CERT = 0x0004,
    NS_DATA_TYPE_CLIENT_VERSION = 0x0005,
    NS_DATA_TYPE_MACHINE_IP = 0x0006,
    NS_DATA_TYPE_POP = 0x0007,
    NS_DATA_TYPE_GATEWAY_HOST = 0x0008,
    NS_DATA_TYPE_ASSIGNED_IP = 0x0009,
    NS_DATA_TYPE_DEVICE_OS = 0x000A,
    NS_DATA_TYPE_DEVICE_TYPE = 0x000B,
    NS_DATA_TYPE_DEVICE_ATTR = 0x000C,
    NS_DATA_TYPE_SSL_DO_NOT_DECRYPT_FLAG = 0x000D,
    NS_DATA_TYPE_CFW_ENABLED = 0x000E,
    NS_DATA_TYPE_SYNTHETIC_PROBE_ID = 0x000F,
    NS_DATA_TYPE_NUM_OF_TLVS = 0x0010,
    NS_DATA_TYPE_PROCESS_NAME = 0x0011,
    NS_DATA_TYPE_PARENT_PROCESS_NAME = 0x0012,
    NS_DATA_TYPE_PROCESS_ID = 0x0013,
    NS_DATA_TYPE_PARENT_PROCESS_ID = 0x0014,

    // below are data types used for forwarder auth protocol
    NS_DATA_TYPE_CLIENT_USERID = 0x1000,
    NS_DATA_TYPE_CLIENT_ORG = 0x1001,
    NS_DATA_TYPE_CLIENT_OU = 0x1002,
    NS_DATA_TYPE_CLIENT_EMAIL = 0x1004,
    NS_DATA_TYPE_CREATED_TIMESTAMP = 0x1005,
};


void
writeFrame(char *buf, uint32_t size, uint16_t type) {
    NsTunnelFrameHeader *frameHdr = (NsTunnelFrameHeader *)buf;
    frameHdr->m_controlVersion = net::hton((uint16_t)(1 | NS_TUNNEL_CONTROL_MASK));
    frameHdr->m_type = net::hton(type);
    frameHdr->m_flagsLength = net::hton(size);
    //std::cout << "writeFrame: size=" << size << std::endl;
}

uint16_t
writeDataTLV(char *frame, uint16_t frameLen, uint16_t type, const char *value, uint16_t valueLen)
{
    if (frameLen < (valueLen + sizeof(NsTunnelDataTLVHeader))) {
        std::cout << "writeDataTLV: overflow " << frameLen << ", valueLen=" << valueLen << std::endl;
        return 0;
    }

    ((NsTunnelDataTLVHeader *)frame)->m_type = net::hton(type);
    ((NsTunnelDataTLVHeader *)frame)->m_length = net::hton(valueLen);

    frame += sizeof(NsTunnelDataTLVHeader);
    memcpy(frame, value, valueLen);
    return valueLen + sizeof(NsTunnelDataTLVHeader);
}

bool
parseDataTLV(const char *frame, uint16_t frameLen, uint16_t &type, const char *&value, uint16_t &valueLen)
{
    size_t hdrSize = sizeof(NsTunnelDataTLVHeader);


    auto tlvHdr = (NsTunnelDataTLVHeader *)(frame);
    type = net::ntoh(tlvHdr->m_type);
    valueLen = net::ntoh(tlvHdr->m_length);
    if (frameLen < hdrSize + valueLen) {
        std::cout << "Not enough data for value. type=" << std::hex << type << std::dec
                  << " length=" << valueLen << " buf offset=" << std::hex
                  << frame;
        return false;
    }

    value = frame + hdrSize;
    return true;
}

enum class NsAuthResult
{
	NS_AUTH_OK = 0,
	NS_AUTH_SYN_AUTH_REQUIRE_ERR,
};

const static char* pass = "";
bool sign_with_private_key_from_PKCS12(PKCS12* p12, const char* data, uint32_t dataLen, std::string& sig, uint32_t& sigLen)
{
    bool rc = false;
    char errBuf[2048] = { 0 };
    long err = 0;
    EVP_MD_CTX* ctx = NULL;
    unsigned char* _sig = NULL;
    const EVP_MD* md = NULL;
    unsigned int sig_len = 0;
    EVP_PKEY* pkey = NULL;
    X509* cert = NULL;
    STACK_OF(X509)* ca = NULL;

    OpenSSL_add_all_algorithms();
    OpenSSL_add_all_digests();
    ERR_load_crypto_strings();

    // parse pkcs12, get private key, public key and chain for other certificates (e.g. intermediate and CA cert)
    if (!PKCS12_parse(p12, pass, &pkey, &cert, &ca)) {
        err = ERR_get_error();
        std::cout << "PKCS12_parse failed, err: " << err << ", errStr: " << ERR_error_string(err, errBuf);
        goto exit;
    }

    //
    // sign the given data using SHA1+RSA
    //

    ctx = EVP_MD_CTX_create();
    if (ctx == NULL) {
        err = ERR_get_error();
        std::cout << "EVP_MD_CTX_create failed, err: " << err << ", errStr: " << ERR_error_string(err, errBuf);
        goto exit;
    }

    md = EVP_get_digestbyname("SHA1");
    if (md == NULL) {
        err = ERR_get_error();
        std::cout << "EVP_get_digestbyname failed, err: " << err << ", errStr: " << ERR_error_string(err, errBuf);
        goto exit;
    }

    if (!EVP_SignInit(ctx, md)) {
        err = ERR_get_error();
        std::cout << "EVP_SignInit failed, err: " << err << ", errStr: " <<  ERR_error_string(err, errBuf);
        goto exit;
    }

    if (!EVP_SignUpdate(ctx, data, dataLen)) {
        err = ERR_get_error();
        std::cout << "EVP_SignUpdate failed, err: " << err << ", errStr: " << ERR_error_string(err, errBuf);
        goto exit;
    }

    sig_len = EVP_PKEY_size(pkey);
    if (!sig_len) {
        err = ERR_get_error();
        std::cout << "EVP_PKEY_size failed, err: " << err << ", errStr: " << ERR_error_string(err, errBuf);
        goto exit;
    }

    _sig = (unsigned char*)malloc(sig_len);
    if (!_sig) {
        std::cout << "malloc fail";
        goto exit;
    }

    memset(_sig, 0, sig_len);

    if (!EVP_SignFinal(ctx, _sig, &sig_len, pkey)) {
        err = ERR_get_error();
        free(_sig);
        _sig = NULL;
        std::cout << "EVP_SignFinal failed, err: " << err << ", errStr:s" <<  ERR_error_string(err, errBuf);
        goto exit;
    }

    //std::cout << "generated sha1+rsa signature, len: " << sig_len << std::endl;
    sig.assign((char*)_sig, sig_len);
    sigLen = sig_len;

    rc = true;

exit:

    if (ctx) {
        EVP_MD_CTX_destroy(ctx);
    }

    if (_sig) {
        free(_sig);
    }

    if (pkey) {
        EVP_PKEY_free(pkey);
    }

    if (cert) {
        X509_free(cert);
    }

    if (ca) {
        sk_X509_pop_free(ca, X509_free);
    }

    return rc;
}

bool sign_with_private_key_from_cert_buffer(std::string clientCertData, const char* data, uint32_t dataLen, std::string& sig, uint32_t& sigLen)
{
    long err = 0;
    bool rc = false;
    BIO* bio = NULL;
    PKCS12* p12 = NULL;
    char errBuf[2048] = { 0 };

    OpenSSL_add_all_algorithms();
    OpenSSL_add_all_digests();
    ERR_load_crypto_strings();

    bio = BIO_new_mem_buf((void*)clientCertData.c_str(), clientCertData.size());
    if (NULL == bio) {
        err = ERR_get_error();
        std::cout << "BIO_new failed, err: " << err << ", errStr: " << ERR_error_string(err, errBuf);
        goto exit;
    }

    // create PKCS12 struct from the given pkcs12 file
    p12 = d2i_PKCS12_bio(bio, NULL);
    if (!p12) {
        err = ERR_get_error();
        std::cout << "d2i_PKCS12_fp failed, err: " << err << ", errStr: " << ERR_error_string(err, errBuf);
        goto exit;
    }

    rc = sign_with_private_key_from_PKCS12(p12, data, dataLen, sig, sigLen);

exit:
    if (bio) {
        BIO_free(bio);
    }

    if (p12) {
        PKCS12_free(p12);
    }

    return rc;
}

bool PKCS12_get_cert_in_x509_from_buffer(const std::string& clientCertData, X509** x509Cert)
{
    long err = 0;
    bool rc = false;
    std::string cert_str;
    BIO* bio = NULL;
    X509* cert = NULL;
    PKCS12* p12 = NULL;
    EVP_PKEY* pkey = NULL;
    char errBuf[2048] = { 0 };

    OpenSSL_add_all_algorithms();
    OpenSSL_add_all_digests();
    ERR_load_crypto_strings();

    bio = BIO_new_mem_buf((void*)clientCertData.c_str(), clientCertData.size());
    if (NULL == bio) {
        err = ERR_get_error();
        std::cout <<  "BIO_new failed, err: " << ERR_error_string(err, errBuf);
        goto exit;
    }

    // create PKCS12 struct from the given pkcs12 file
    p12 = d2i_PKCS12_bio(bio, NULL);
    if (!p12) {
        err = ERR_get_error();
        std::cout << "d2i_PKCS12_fp failed, err: " << ERR_error_string(err, errBuf);
        goto exit;
    }

    // parse pkcs12, get private key, public key and chain for other certificates e.g. intermediate and CA cert
    if (!PKCS12_parse(p12, pass, &pkey, &cert, NULL)) {
        err = ERR_get_error();
        std::cout << "failed to parse certificate from pkcs12, err: " << ERR_error_string(err, errBuf);
        goto exit;
    }
    *x509Cert = cert;
    rc = true;

exit:
    if (NULL != p12) {
        PKCS12_free(p12);
    }

    if (NULL != pkey) {
        EVP_PKEY_free(pkey);
    }

    if (bio) {
        BIO_free(bio);
    }

    return rc;
}

bool PKCS12_get_cert_in_der_from_buffer(std::string clientCertData, std::string& cert)
{
    int len = 0;
    long err = 0;
    X509* x509Cert = nullptr;
    bool status = false;
    char errBuf[2048] = { 0 };
    unsigned char* buf = NULL;

    if (!PKCS12_get_cert_in_x509_from_buffer(clientCertData, &x509Cert)) {
        std::cout << "failed to get client cert in X509 format";
        return false;
    }

    // convert cert to der
    len = i2d_X509(x509Cert, &buf);
    if (len < 0) {
        err = ERR_get_error();
        std::cout << "failed to convert x509 cert to der, err: " << ERR_error_string(err, errBuf);
        goto exit;
    }

    cert.assign((char*)buf, len);
    OPENSSL_free(buf);
    status = true;

exit:
    if (NULL != x509Cert) {
        X509_free(x509Cert);
    }

    return status;
}

bool PEM_get_cert_in_der_from_buffer(std::string certData, std::string& cert)
{
    bool rc = false;
    char errBuf[2048] = { 0 };
    long err = 0;
    std::string cert_str;
    X509* crt = NULL;
    int len = 0;
    BIO* bio = NULL;
    unsigned char* buf = NULL;

    OpenSSL_add_all_algorithms();
    OpenSSL_add_all_digests();
    ERR_load_crypto_strings();

    bio = BIO_new_mem_buf((void*)certData.c_str(), certData.size());
    if (NULL == bio) {
        err = ERR_get_error();
        std::cout << "BIO_new_mem_buf failed, err: " << ERR_error_string(err, errBuf);
        goto exit;
    }

    crt = PEM_read_bio_X509(bio, NULL, NULL, NULL);
    if (!crt) {
        err = ERR_get_error();
        std::cout << "PEM_read_X509 failed, err: " << ERR_error_string(err, errBuf);
        goto exit;
    }

    // convert cert to der
    len = i2d_X509(crt, &buf);
    if (len < 0) {
        err = ERR_get_error();
        std::cout <<  "i2d_X509 failed, err: " <<  ERR_error_string(err, errBuf);
        goto exit;
    }

    cert.assign((char*)buf, len);
    OPENSSL_free(buf);
    rc = true;

exit:
    if (bio) {
        BIO_free_all(bio);
    }

    if (crt) {
        X509_free(crt);
    }

    return rc;
}

std::ifstream tenantCerfile {"/home/kevint/perftenant059-tenant_cert.pem"};
std::string tenantCertPem {std::istreambuf_iterator<char>(tenantCerfile), std::istreambuf_iterator<char>()};
std::string tenantCertDer;

std::ifstream userCerfile {"/home/kevint/perftenant059-kevint_usercert.pkcs12"};
std::string userCertPkcs12 {std::istreambuf_iterator<char>(userCerfile), std::istreambuf_iterator<char>()};
std::string userCertDer;


uint16_t g_synTunnelFrameLen{0};
constexpr uint16_t g_synTunnelFrameSize{256};
char g_synTunnelFrame[g_synTunnelFrameSize];
void prepareSynTunnelFrame() {
    std::string clientVersion = "999";
    std::string deviceOS = "UT";
    
    char *data = NS_FRAME_DATA(g_synTunnelFrame);
    g_synTunnelFrameLen += writeDataTLV(data, 256 - g_synTunnelFrameLen, NS_DATA_TYPE_CLIENT_VERSION, clientVersion.c_str(), clientVersion.length());

    data = NS_FRAME_DATA(g_synTunnelFrame) + g_synTunnelFrameLen;
    g_synTunnelFrameLen += writeDataTLV(data, 256 - g_synTunnelFrameLen, NS_DATA_TYPE_DEVICE_OS, deviceOS.c_str(), deviceOS.length());

    writeFrame(g_synTunnelFrame, g_synTunnelFrameLen, NS_FRAME_TYPE_SYN_TUNNEL);
    g_synTunnelFrameLen += sizeof(NsTunnelFrameHeader);
}

uint16_t g_synTunnelAuthResponseFrameLen{0};
void prepareSynTunnelAuthResponseFrame(char *buf, uint16_t bufSize) {
    std::string machineIp = "10.66.2.161";

    uint16_t dataLen = sizeof(NsTunnelDataTLVHeader) + 256; // Skip "Signed Nonce" TLV
    char *data = NS_FRAME_DATA(buf) + dataLen;
    dataLen += writeDataTLV(data, bufSize - dataLen, NS_DATA_TYPE_MACHINE_IP, machineIp.c_str(), machineIp.length());

    data = NS_FRAME_DATA(buf) + dataLen;
    dataLen += writeDataTLV(data, bufSize - dataLen, NS_DATA_TYPE_AUTH_CERT, userCertDer.c_str(), userCertDer.length());

    data = NS_FRAME_DATA(buf) + dataLen;
    dataLen += writeDataTLV(data, bufSize - dataLen, NS_DATA_TYPE_AUTH_CERT, tenantCertDer.c_str(), tenantCertDer.length());

    writeFrame(buf, dataLen, NS_FRAME_TYPE_SYN_TUNNEL_AUTH_RESPONSE);

    if (g_synTunnelAuthResponseFrameLen == 0) {
        g_synTunnelAuthResponseFrameLen = dataLen + sizeof(NsTunnelFrameHeader);
    }
}

uint16_t g_bufSize{3072};
uint16_t g_dataSize = g_bufSize - sizeof(NsTunnelFrameHeader);

class NsClient {
private:
    char *m_buf;

public:
    NsClient() {
        m_buf = new char[g_bufSize];
    }

    char *buf() {return m_buf;}

    future<>
    sendSynTunnel(streams *strms) {
        return strms->out.write(g_synTunnelFrame, g_synTunnelFrameLen).then([strms]() {
            return strms->out.flush();
        });
    }

    future<>
    recvSendSynTunnelAuth(streams *strms) {
        return strms->in.read_exactly(28).then([this, strms](temporary_buffer<char> buf) {
            const char *frame = buf.get();
            uint16_t frameLen = buf.size();
            const char *nonce;
            uint16_t nonceLen, tlvType;

            if (frameLen < 28) {
                auto localAddr = strms->s.local_address();
                std::cout << "IO error: port=" << localAddr.port() << ", frameLen=" << frameLen << std::endl;
                return make_ready_future<>();
            }

            parseDataTLV(frame + sizeof(NsTunnelFrameHeader), frameLen, tlvType, nonce, nonceLen);

            char *nsData = m_buf + sizeof(NsTunnelFrameHeader); // Move to data part.
            uint16_t dataLen = 0;   // Reset it for a new frame.

            //std::cout << "m_dataSize=" << m_dataSize << ", nonceLen=" << nonceLen << std::endl;

            std::string sign;
            uint32_t signLen;
            if (!sign_with_private_key_from_cert_buffer(userCertPkcs12, nonce, nonceLen, sign, signLen)) {
                std::cout << "failed to sign nonce";
            }

            char *data = nsData;
            dataLen += writeDataTLV(data, g_dataSize - dataLen, NS_DATA_TYPE_AUTH_SIGNED_NONCE, sign.c_str(), sign.length());

            return strms->out.write(m_buf, g_synTunnelAuthResponseFrameLen).then([strms]() {
                return strms->out.flush();
            });
        });
    }

    future<streams *>
    start(ipv4_addr server_addr, seastar::shared_ptr<tls::certificate_credentials> certs) {
        tls::tls_options options;
        return tls::connect(certs, server_addr, options).then([this](::connected_socket s) {
            auto strms = new streams(std::move(s));
            using namespace std::chrono_literals;
            return sendSynTunnel(strms).then([this, strms]() {
//            return seastar::sleep(0s).then([this, strms]() {
                return recvSendSynTunnelAuth(strms).then([this, strms]() {
//                  delete m_buf;
//                  return strms->out.close().then([strms]() {
//                  return strms->in.close();
                    return strms;
                });
//            });
            });
        });
    }
};

uint32_t g_count = 0;
uint32_t g_clientNum = 40000;
auto g_clients = std::make_unique<NsClient[]>(g_clientNum);

class Benchmark {
public:
    struct Params {
        Params() {}

        bool wait;          // Don't close connection.
        uint32_t iteration;
        uint32_t parallel;

        seastar::shared_ptr<tls::certificate_credentials> certPtr;
        ipv4_addr gwIp;     // NSGW IP
    };

    Benchmark(Params p) : m_params(p) {}

    future<> perfEstablishTunnel() {
        auto range = std::views::iota(size_t(0), m_params.iteration);
        return do_for_each(range, [this](int i) {
            size_t begin = i * m_params.parallel;
            size_t end = begin + m_params.parallel;
            return parallel_for_each(std::views::iota(begin, end), [this] (int index) {
                return g_clients[index].start(m_params.gwIp, m_params.certPtr).then([index] (auto strms) {
                    //g_clients[index].m_strms = strms;
                    ++g_count;
                });
            }).then([] () {
                std::cout << g_count << " clients connected..." << std::endl;
            });

        }).then([this]() {
            if (!m_params.wait) engine().exit(0);
        });
    
    }

private:
    Params m_params;
};

int main(int ac, char** av) {
    /* Load Multiple providers into the default (NULL) library context */
    OSSL_PROVIDER *legacy = OSSL_PROVIDER_load(NULL, "legacy");
    if (legacy == NULL) {
        printf("Failed to load Legacy provider\n");
        exit(EXIT_FAILURE);
    }

    OSSL_PROVIDER *deflt = OSSL_PROVIDER_load(NULL, "default");
    if (deflt == NULL) {
        printf("Failed to load Default provider\n");
        OSSL_PROVIDER_unload(legacy);
        exit(EXIT_FAILURE);
    }
    
    if (!PKCS12_get_cert_in_der_from_buffer(userCertPkcs12, userCertDer)) {
        std::cout << "failed to get client cert in DER format";
    }

    if (!PEM_get_cert_in_der_from_buffer(tenantCertPem, tenantCertDer)) {
        std::cout << "failed to get tenant cert in DER format";
    }

    // Pre-build frame for const TLV.
    prepareSynTunnelFrame();
    for (uint32_t i = 0; i < g_clientNum; ++i) {
        prepareSynTunnelAuthResponseFrame(g_clients[i].buf(), g_bufSize);
    }

    app_template app;
    app.add_options()
                    ("port", bpo::value<uint16_t>()->default_value(10000), "Remote port")
                    ("address", bpo::value<std::string>()->default_value("127.0.0.1"), "Remote address")
                    ("trust,t", bpo::value<std::string>(), "Trust store")
                    ("msg,m", bpo::value<std::string>(), "Message to send")
                    ("parallel,p", bpo::value<uint32_t>()->default_value(1), "Burst X requests")
                    ("iterations,i", bpo::value<uint32_t>()->default_value(1), "Repeat X times")
                    ("read-response,r", bpo::value<bool>()->default_value(true)->implicit_value(true), "Read echoed message")
                    ("verbose,v", bpo::value<bool>()->default_value(false)->implicit_value(true), "Verbose operation")
                    ("wait,w", bpo::value<bool>()->default_value(false)->implicit_value(true), "Won't close connection")
                    ("server-name,s", bpo::value<std::string>(), "Expected server name")
                    ;


    Benchmark::Params params;
    return app.run_deprecated(ac, av, [&] {
        auto&& config = app.configuration();
        uint16_t port = config["port"].as<uint16_t>();
        auto addr = config["address"].as<std::string>();
        params.iteration = config["iterations"].as<uint32_t>();
        params.parallel = config["parallel"].as<uint32_t>();
        params.wait = config["wait"].as<bool>();

        std::cout << "Starting: " << seastar::smp::count << " threads." << std::endl;

        params.certPtr = ::make_shared<tls::certificate_credentials>();
        auto f = make_ready_future();

        if (config.count("trust")) {
            f = params.certPtr->set_x509_trust_file(config["trust"].as<std::string>(), tls::x509_crt_format::PEM);
        }

        params.gwIp = std::move(ipv4_addr(addr, port));
        auto bmPtr = seastar::make_shared<Benchmark>(params);
        

        return bmPtr->perfEstablishTunnel();
    });
}
