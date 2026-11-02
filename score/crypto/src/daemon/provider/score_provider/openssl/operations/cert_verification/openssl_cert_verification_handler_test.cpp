/********************************************************************************
 * Copyright (c) 2026 Contributors to the Eclipse Foundation
 *
 * See the NOTICE file(s) distributed with this work for additional
 * information regarding copyright ownership.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Apache License Version 2.0 which is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * SPDX-License-Identifier: Apache-2.0
 ********************************************************************************/

// Path-validation tests for VerifyCertificatePath().
//
// Every certificate and CRL is generated in-process so that each test controls exactly one property
// (validity window, issuer key, CA flag, path length, key usage, digest, critical extensions, CRL
// contents and freshness). All verifications run at a fixed time, so the tests do not depend on the
// wall clock.

#include "score/crypto/src/daemon/provider/score_provider/openssl/operations/cert_verification/openssl_cert_verification_handler.hpp"

#include "score/crypto/src/api/types/certificate.hpp"
#include "score/crypto/src/daemon/cert_management/interfaces/cert_object.hpp"
#include "score/crypto/src/daemon/cert_management/interfaces/cert_types.hpp"
#include "score/crypto/src/daemon/provider/score_provider/openssl/cert_management/openssl_cert_parser.hpp"

#include <gtest/gtest.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace score::crypto::daemon::provider::score_provider::openssl::handler
{
namespace
{

using cert_management_types = ::score::crypto::daemon::cert_management::CertObject;
using CertSptr = ::score::crypto::daemon::cert_management::CertObject::Sptr;
using CrlData = ::score::crypto::daemon::cert_management::CrlData;
using Input = score_provider::operations::cert_verification::ScoreCertVerificationHandler::VerificationInput;
using Outcome = score_provider::operations::cert_verification::ScoreCertVerificationHandler::VerifyOutcome;
using R = ::score::crypto::CertVerifyResult;
using Error = common::DaemonErrorCode;

// 2027-01-15T08:00:00Z. Every validity window below is relative to this instant.
constexpr std::int64_t kNow = 1'800'000'000;
constexpr std::int64_t kDay = 24 * 60 * 60;
constexpr std::int64_t kYear = 365 * kDay;

struct PkeyDeleter
{
    void operator()(EVP_PKEY* p) const noexcept
    {
        EVP_PKEY_free(p);
    }
};
using Key = std::shared_ptr<EVP_PKEY>;

Key NewKey()
{
    return Key(EVP_EC_gen("P-256"), PkeyDeleter{});
}

/// Options for one generated certificate. Defaults produce a valid end-entity certificate.
struct CertSpec
{
    std::string cn;
    long serial{1};
    std::int64_t not_before{kNow - kYear};
    std::int64_t not_after{kNow + kYear};
    bool ca{false};
    std::optional<long> path_len;
    /// Value for keyUsage, or empty to omit the extension.
    std::string key_usage;
    const EVP_MD* digest{EVP_sha256()};
    bool unknown_critical_extension{false};
};

struct Issued
{
    std::shared_ptr<X509> cert;
    Key key;
};

void AddExt(X509* cert, X509* issuer, int nid, const std::string& value)
{
    X509V3_CTX ctx;
    X509V3_set_ctx_nodb(&ctx);
    X509V3_set_ctx(&ctx, issuer, cert, nullptr, nullptr, 0);
    X509_EXTENSION* ext = X509V3_EXT_conf_nid(nullptr, &ctx, nid, value.c_str());
    ASSERT_NE(ext, nullptr) << "extension " << nid << "=" << value;
    ASSERT_EQ(X509_add_ext(cert, ext, -1), 1);
    X509_EXTENSION_free(ext);
}

/// Issues a certificate for @p subject_key. With @p issuer == nullptr the certificate is self-signed.
/// @p signing_key overrides the key used for the signature (to forge one), defaulting to the issuer key.
Issued IssueWith(const CertSpec& spec, const Issued* issuer, Key subject_key, Key signing_key = {})
{
    std::shared_ptr<X509> cert(X509_new(), X509_free);
    X509_set_version(cert.get(), 2);
    ASN1_INTEGER_set(X509_get_serialNumber(cert.get()), spec.serial);
    ASN1_TIME_set(X509_getm_notBefore(cert.get()), static_cast<time_t>(spec.not_before));
    ASN1_TIME_set(X509_getm_notAfter(cert.get()), static_cast<time_t>(spec.not_after));
    X509_set_pubkey(cert.get(), subject_key.get());

    X509_NAME* name = X509_get_subject_name(cert.get());
    X509_NAME_add_entry_by_txt(
        name, "CN", MBSTRING_ASC, reinterpret_cast<const unsigned char*>(spec.cn.c_str()), -1, -1, 0);
    X509_set_issuer_name(cert.get(), issuer ? X509_get_subject_name(issuer->cert.get()) : name);

    X509* issuer_cert = issuer ? issuer->cert.get() : cert.get();
    AddExt(cert.get(), issuer_cert, NID_subject_key_identifier, "hash");
    AddExt(cert.get(), issuer_cert, NID_authority_key_identifier, "keyid:always");
    if (spec.ca)
    {
        std::string bc = "critical,CA:TRUE";
        if (spec.path_len.has_value())
            bc += ",pathlen:" + std::to_string(*spec.path_len);
        AddExt(cert.get(), issuer_cert, NID_basic_constraints, bc);
    }
    else
    {
        AddExt(cert.get(), issuer_cert, NID_basic_constraints, "critical,CA:FALSE");
    }
    if (!spec.key_usage.empty())
        AddExt(cert.get(), issuer_cert, NID_key_usage, spec.key_usage);
    if (spec.unknown_critical_extension)
    {
        ASN1_OBJECT* oid = OBJ_txt2obj("1.3.6.1.4.1.55555.1.1", 1);
        ASN1_OCTET_STRING* data = ASN1_OCTET_STRING_new();
        const unsigned char der_null[] = {0x05, 0x00};
        ASN1_OCTET_STRING_set(data, der_null, sizeof(der_null));
        X509_EXTENSION* ext = X509_EXTENSION_create_by_OBJ(nullptr, oid, 1, data);
        X509_add_ext(cert.get(), ext, -1);
        X509_EXTENSION_free(ext);
        ASN1_OCTET_STRING_free(data);
        ASN1_OBJECT_free(oid);
    }

    Key signer = signing_key ? signing_key : (issuer ? issuer->key : subject_key);
    EXPECT_GT(X509_sign(cert.get(), signer.get(), spec.digest), 0);
    return Issued{cert, subject_key};
}

Issued Issue(const CertSpec& spec, const Issued* issuer)
{
    return IssueWith(spec, issuer, NewKey());
}

CertSpec RootSpec(const std::string& cn = "Test Root CA")
{
    CertSpec s;
    s.cn = cn;
    s.ca = true;
    s.key_usage = "critical,keyCertSign,cRLSign";
    s.not_before = kNow - 5 * kYear;
    s.not_after = kNow + 5 * kYear;
    return s;
}

CertSpec IntermediateSpec(const std::string& cn = "Test Intermediate CA")
{
    CertSpec s = RootSpec(cn);
    s.serial = 2;
    return s;
}

CertSpec LeafSpec(const std::string& cn = "ecu.example")
{
    CertSpec s;
    s.cn = cn;
    s.serial = 3;
    s.key_usage = "critical,digitalSignature";
    return s;
}

struct CrlSpec
{
    std::vector<long> revoked_serials;
    std::int64_t last_update{kNow - kDay};
    std::int64_t next_update{kNow + 7 * kDay};
    std::optional<long> crl_number{1};
};

std::vector<std::uint8_t> Der(X509* cert)
{
    const int len = i2d_X509(cert, nullptr);
    std::vector<std::uint8_t> out(static_cast<std::size_t>(len));
    unsigned char* p = out.data();
    i2d_X509(cert, &p);
    return out;
}

/// Issues a CRL in the name of @p issuer, signed by @p signing_key (defaults to the issuer key).
CrlData::Sptrc MakeCrl(const Issued& issuer, const CrlSpec& spec, Key signing_key = {})
{
    std::unique_ptr<X509_CRL, decltype(&X509_CRL_free)> crl(X509_CRL_new(), &X509_CRL_free);
    X509_CRL_set_version(crl.get(), 1);
    X509_CRL_set_issuer_name(crl.get(), X509_get_subject_name(issuer.cert.get()));
    std::unique_ptr<ASN1_TIME, decltype(&ASN1_TIME_free)> last(ASN1_TIME_new(), &ASN1_TIME_free);
    std::unique_ptr<ASN1_TIME, decltype(&ASN1_TIME_free)> next(ASN1_TIME_new(), &ASN1_TIME_free);
    ASN1_TIME_set(last.get(), static_cast<time_t>(spec.last_update));
    ASN1_TIME_set(next.get(), static_cast<time_t>(spec.next_update));
    X509_CRL_set1_lastUpdate(crl.get(), last.get());
    X509_CRL_set1_nextUpdate(crl.get(), next.get());
    for (long serial : spec.revoked_serials)
    {
        X509_REVOKED* revoked = X509_REVOKED_new();
        ASN1_INTEGER* s = ASN1_INTEGER_new();
        ASN1_INTEGER_set(s, serial);
        X509_REVOKED_set_serialNumber(revoked, s);
        X509_REVOKED_set_revocationDate(revoked, last.get());
        X509_CRL_add0_revoked(crl.get(), revoked);
        ASN1_INTEGER_free(s);
    }
    if (spec.crl_number.has_value())
    {
        ASN1_INTEGER* number = ASN1_INTEGER_new();
        ASN1_INTEGER_set(number, *spec.crl_number);
        X509_CRL_add1_ext_i2d(crl.get(), NID_crl_number, number, 0, 0);
        ASN1_INTEGER_free(number);
    }
    X509_CRL_sort(crl.get());
    Key signer = signing_key ? signing_key : issuer.key;
    EXPECT_GT(X509_CRL_sign(crl.get(), signer.get(), EVP_sha256()), 0);

    const int len = i2d_X509_CRL(crl.get(), nullptr);
    std::vector<std::uint8_t> bytes(static_cast<std::size_t>(len));
    unsigned char* p = bytes.data();
    i2d_X509_CRL(crl.get(), &p);
    auto data = std::make_shared<CrlData>();
    data->bytes = std::move(bytes);
    data->format = ::score::crypto::FormatType::kDer;
    return data;
}

class VerifyCertificatePathTest : public ::testing::Test
{
  protected:
    CertSptr Obj(const Issued& issued)
    {
        const auto der = Der(issued.cert.get());
        auto parsed = m_parser.ParseCertificate(der.data(), der.size(), ::score::crypto::FormatType::kDer);
        EXPECT_TRUE(parsed.has_value());
        return parsed.has_value() ? parsed.value() : nullptr;
    }

    /// The common three-level PKI: root -> intermediate -> leaf.
    void SetUp() override
    {
        m_root = Issue(RootSpec(), nullptr);
        m_intermediate = Issue(IntermediateSpec(), &m_root);
        m_leaf = Issue(LeafSpec(), &m_intermediate);
    }

    Input BaseInput(const Issued& leaf)
    {
        Input input;
        input.leaf = Obj(leaf);
        input.chain = {Obj(m_intermediate)};
        input.trusted = {Obj(m_root)};
        input.verification_time_epoch_s = kNow;
        return input;
    }

    Input BaseInput()
    {
        return BaseInput(m_leaf);
    }

    static void WithCrls(Input& input, std::vector<CrlData::Sptrc> crls, bool best_effort = false)
    {
        input.revocation_policy = static_cast<std::uint8_t>(::score::crypto::RevocationCheckPolicy::kCrlOnly);
        input.revocation_coverage_policy = best_effort ? ::score::crypto::RevocationCoveragePolicy::kBestEffort
                                                       : ::score::crypto::RevocationCoveragePolicy::kFailClosed;
        input.crls = std::move(crls);
    }

    /// True when the path is not accepted, whether reported as a result code or as an error.
    static bool IsRejected(const Expected<Outcome, Error>& res)
    {
        return !res.has_value() || res.value().result_code != static_cast<std::uint8_t>(R::kValid);
    }

    static ::testing::AssertionResult HasResult(const Expected<Outcome, Error>& res, R expected)
    {
        if (!res.has_value())
            return ::testing::AssertionFailure()
                   << "returned error 0x" << std::hex << static_cast<int>(res.error()) << " instead of result "
                   << std::dec << static_cast<int>(expected);
        if (res.value().result_code != static_cast<std::uint8_t>(expected))
            return ::testing::AssertionFailure() << "result " << static_cast<int>(res.value().result_code)
                                                 << " instead of " << static_cast<int>(expected);
        return ::testing::AssertionSuccess();
    }

    OpenSslCertParser m_parser{common::ProviderId{1U}};
    Issued m_root;
    Issued m_intermediate;
    Issued m_leaf;
};

// ---------------------------------------------------------------------------
// Accepted paths
// ---------------------------------------------------------------------------

TEST_F(VerifyCertificatePathTest, ValidChainIsAccepted)
{
    EXPECT_TRUE(HasResult(VerifyCertificatePath(BaseInput()), R::kValid));
}

TEST_F(VerifyCertificatePathTest, ValidChainReturnsLeafFirstChainWhenEvidenceRequested)
{
    Input input = BaseInput();
    input.evidence_mode = ::score::crypto::VerificationEvidenceMode::kChain;
    const auto res = VerifyCertificatePath(input);
    ASSERT_TRUE(HasResult(res, R::kValid));
    ASSERT_EQ(res.value().chain.size(), 3U);
    EXPECT_EQ(res.value().chain[0]->GetSubject(), input.leaf->GetSubject());
    EXPECT_EQ(res.value().chain[1]->GetSubject(), input.chain[0]->GetSubject());
    EXPECT_EQ(res.value().chain[2]->GetSubject(), input.trusted[0]->GetSubject());
}

TEST_F(VerifyCertificatePathTest, IntermediateFoundAmongAdditionalCertificates)
{
    Input input = BaseInput();
    input.additional = input.chain;
    input.chain.clear();
    EXPECT_TRUE(HasResult(VerifyCertificatePath(input), R::kValid));
}

TEST_F(VerifyCertificatePathTest, UnrelatedCertificatesInChainDoNotAppearInVerifiedChain)
{
    Input input = BaseInput();
    const Issued other_root = Issue(RootSpec("Unrelated Root"), nullptr);
    input.chain.push_back(Obj(other_root));
    input.additional.push_back(Obj(Issue(LeafSpec("unrelated.example"), &other_root)));
    input.evidence_mode = ::score::crypto::VerificationEvidenceMode::kChain;
    const auto res = VerifyCertificatePath(input);
    ASSERT_TRUE(HasResult(res, R::kValid));
    EXPECT_EQ(res.value().chain.size(), 3U);
}

TEST_F(VerifyCertificatePathTest, StandaloneTrustedIntermediateTerminatesThePath)
{
    // Explicitly trusted certificates are anchors by definition, so pinning an intermediate is allowed.
    Input input = BaseInput();
    input.chain.clear();
    input.trusted = {Obj(m_intermediate)};
    EXPECT_TRUE(HasResult(VerifyCertificatePath(input), R::kValid));
}

TEST_F(VerifyCertificatePathTest, TrustStoreTerminatedPolicyAcceptsIntermediateAnchor)
{
    Input input = BaseInput();
    input.chain.clear();
    input.trusted = {Obj(m_intermediate)};
    input.trust_store_node_id = 42U;
    input.chain_termination_policy =
        static_cast<std::uint8_t>(::score::crypto::ChainTerminationPolicy::kTrustStoreTerminated);
    EXPECT_TRUE(HasResult(VerifyCertificatePath(input), R::kValid));
}

TEST_F(VerifyCertificatePathTest, RevocationCheckAcceptsUnrevokedChain)
{
    Input input = BaseInput();
    WithCrls(input, {MakeCrl(m_root, {}), MakeCrl(m_intermediate, {})});
    EXPECT_TRUE(HasResult(VerifyCertificatePath(input), R::kValid));
}

TEST_F(VerifyCertificatePathTest, NewestCrlByNumberIsUsed)
{
    // The issuer revoked the leaf in CRL #2; an older CRL #1 without the entry must not win.
    Input input = BaseInput();
    CrlSpec older;
    older.crl_number = 1;
    CrlSpec newer;
    newer.crl_number = 2;
    newer.revoked_serials = {3};
    WithCrls(input, {MakeCrl(m_root, {}), MakeCrl(m_intermediate, older), MakeCrl(m_intermediate, newer)});
    EXPECT_TRUE(HasResult(VerifyCertificatePath(input), R::kRevoked));
}

// ---------------------------------------------------------------------------
// Validity periods
// ---------------------------------------------------------------------------

TEST_F(VerifyCertificatePathTest, ExpiredLeafIsRejected)
{
    CertSpec spec = LeafSpec();
    spec.not_before = kNow - 2 * kYear;
    spec.not_after = kNow - kDay;
    EXPECT_TRUE(HasResult(VerifyCertificatePath(BaseInput(Issue(spec, &m_intermediate))), R::kExpired));
}

TEST_F(VerifyCertificatePathTest, NotYetValidLeafIsRejected)
{
    CertSpec spec = LeafSpec();
    spec.not_before = kNow + kDay;
    EXPECT_TRUE(HasResult(VerifyCertificatePath(BaseInput(Issue(spec, &m_intermediate))), R::kNotYetValid));
}

TEST_F(VerifyCertificatePathTest, ExpiredIntermediateIsRejected)
{
    CertSpec spec = IntermediateSpec();
    spec.not_after = kNow - kDay;
    m_intermediate = Issue(spec, &m_root);
    m_leaf = Issue(LeafSpec(), &m_intermediate);
    EXPECT_TRUE(HasResult(VerifyCertificatePath(BaseInput()), R::kExpired));
}

TEST_F(VerifyCertificatePathTest, VerificationTimeIsHonoured)
{
    // Valid "now", but not at a verification time after its notAfter.
    Input input = BaseInput();
    input.verification_time_epoch_s = kNow + 2 * kYear;
    EXPECT_TRUE(HasResult(VerifyCertificatePath(input), R::kExpired));
}

// ---------------------------------------------------------------------------
// Signatures and path building
// ---------------------------------------------------------------------------

TEST_F(VerifyCertificatePathTest, LeafWithForgedSignatureIsRejected)
{
    // Issuer name and AKID point at the intermediate, but the signature is made with another key.
    const Issued forged = IssueWith(LeafSpec(), &m_intermediate, NewKey(), NewKey());
    const auto res = VerifyCertificatePath(BaseInput(forged));
    EXPECT_TRUE(IsRejected(res));
    EXPECT_TRUE(HasResult(res, R::kSignatureInvalid));
}

TEST_F(VerifyCertificatePathTest, IntermediateWithForgedSignatureIsRejected)
{
    m_intermediate = IssueWith(IntermediateSpec(), &m_root, NewKey(), NewKey());
    m_leaf = Issue(LeafSpec(), &m_intermediate);
    const auto res = VerifyCertificatePath(BaseInput());
    EXPECT_TRUE(IsRejected(res));
    EXPECT_TRUE(HasResult(res, R::kSignatureInvalid));
}

TEST_F(VerifyCertificatePathTest, MissingIntermediateIsChainIncomplete)
{
    Input input = BaseInput();
    input.chain.clear();
    EXPECT_TRUE(HasResult(VerifyCertificatePath(input), R::kChainIncomplete));
}

TEST_F(VerifyCertificatePathTest, ChainToADifferentRootIsRejected)
{
    Input input = BaseInput();
    input.trusted = {Obj(Issue(RootSpec("Other Root"), nullptr))};
    EXPECT_TRUE(IsRejected(VerifyCertificatePath(input)));
}

TEST_F(VerifyCertificatePathTest, RootLookalikeWithSameNameButOtherKeyIsRejected)
{
    // An attacker-made root with the genuine root's name must not anchor the genuine chain.
    Input input = BaseInput();
    input.trusted = {Obj(Issue(RootSpec(), nullptr))};
    EXPECT_TRUE(IsRejected(VerifyCertificatePath(input)));
}

TEST_F(VerifyCertificatePathTest, UntrustedSelfSignedLeafIsNoRootFound)
{
    Input input = BaseInput(Issue(LeafSpec("self.example"), nullptr));
    input.chain.clear();
    EXPECT_TRUE(HasResult(VerifyCertificatePath(input), R::kNoRootFound));
}

TEST_F(VerifyCertificatePathTest, NoTrustAnchorsIsNoRootFound)
{
    Input input = BaseInput();
    input.trusted.clear();
    EXPECT_TRUE(HasResult(VerifyCertificatePath(input), R::kNoRootFound));
}

TEST_F(VerifyCertificatePathTest, IntermediateIsNotAnAnchorInTrustStoreModeWithRootRequired)
{
    Input input = BaseInput();
    input.chain.clear();
    input.trusted = {Obj(m_intermediate)};
    input.trust_store_node_id = 42U;
    input.chain_termination_policy = static_cast<std::uint8_t>(::score::crypto::ChainTerminationPolicy::kRootRequired);
    EXPECT_TRUE(IsRejected(VerifyCertificatePath(input)));
}

// ---------------------------------------------------------------------------
// CA constraints. These paths must be rejected, and the rejection must be reported as a verification
// result rather than as an infrastructure error, so that callers do not treat it as retryable.
// ---------------------------------------------------------------------------

TEST_F(VerifyCertificatePathTest, IntermediateWithoutCaFlagIsRejected)
{
    CertSpec spec = IntermediateSpec();
    spec.ca = false;
    spec.key_usage.clear();
    m_intermediate = Issue(spec, &m_root);
    m_leaf = Issue(LeafSpec(), &m_intermediate);
    const auto res = VerifyCertificatePath(BaseInput());
    EXPECT_TRUE(IsRejected(res));
    EXPECT_TRUE(res.has_value()) << "rejection reported as error 0x" << std::hex << static_cast<int>(res.error());
}

TEST_F(VerifyCertificatePathTest, IntermediateWithoutKeyCertSignIsRejected)
{
    CertSpec spec = IntermediateSpec();
    spec.key_usage = "critical,digitalSignature";
    m_intermediate = Issue(spec, &m_root);
    m_leaf = Issue(LeafSpec(), &m_intermediate);
    const auto res = VerifyCertificatePath(BaseInput());
    EXPECT_TRUE(IsRejected(res));
    EXPECT_TRUE(res.has_value()) << "rejection reported as error 0x" << std::hex << static_cast<int>(res.error());
}

TEST_F(VerifyCertificatePathTest, PathLengthConstraintIsEnforced)
{
    // root -> intermediate(pathlen:0) -> sub-CA -> leaf: the sub-CA exceeds the intermediate's path length.
    CertSpec spec = IntermediateSpec();
    spec.path_len = 0;
    m_intermediate = Issue(spec, &m_root);
    CertSpec sub_spec = IntermediateSpec("Test Sub CA");
    sub_spec.serial = 5;
    const Issued sub = Issue(sub_spec, &m_intermediate);
    Input input = BaseInput(Issue(LeafSpec(), &sub));
    input.chain = {Obj(sub), Obj(m_intermediate)};
    const auto res = VerifyCertificatePath(input);
    EXPECT_TRUE(IsRejected(res));
    EXPECT_TRUE(res.has_value()) << "rejection reported as error 0x" << std::hex << static_cast<int>(res.error());
}

TEST_F(VerifyCertificatePathTest, UnknownCriticalExtensionIsRejected)
{
    CertSpec spec = LeafSpec();
    spec.unknown_critical_extension = true;
    const auto res = VerifyCertificatePath(BaseInput(Issue(spec, &m_intermediate)));
    EXPECT_TRUE(IsRejected(res));
    EXPECT_TRUE(res.has_value()) << "rejection reported as error 0x" << std::hex << static_cast<int>(res.error());
}

TEST_F(VerifyCertificatePathTest, Sha1SignedIntermediateIsRejected)
{
    CertSpec spec = IntermediateSpec();
    spec.digest = EVP_sha1();
    m_intermediate = Issue(spec, &m_root);
    m_leaf = Issue(LeafSpec(), &m_intermediate);
    const auto res = VerifyCertificatePath(BaseInput());
    EXPECT_TRUE(IsRejected(res));
    EXPECT_TRUE(res.has_value()) << "rejection reported as error 0x" << std::hex << static_cast<int>(res.error());
}

TEST_F(VerifyCertificatePathTest, Sha1SignedLeafIsRejected)
{
    CertSpec spec = LeafSpec();
    spec.digest = EVP_sha1();
    const auto res = VerifyCertificatePath(BaseInput(Issue(spec, &m_intermediate)));
    EXPECT_TRUE(HasResult(res, R::kInvalidPurpose));
}

TEST_F(VerifyCertificatePathTest, Rsa1024LeafKeyIsRejected)
{
    const Key weak_key(EVP_RSA_gen(1024), PkeyDeleter{});
    ASSERT_NE(weak_key, nullptr);
    const auto res = VerifyCertificatePath(BaseInput(IssueWith(LeafSpec(), &m_intermediate, weak_key)));
    EXPECT_TRUE(HasResult(res, R::kInvalidPurpose));
}

TEST_F(VerifyCertificatePathTest, Rsa2048LeafKeyIsAccepted)
{
    const Key key(EVP_RSA_gen(2048), PkeyDeleter{});
    ASSERT_NE(key, nullptr);
    EXPECT_TRUE(HasResult(VerifyCertificatePath(BaseInput(IssueWith(LeafSpec(), &m_intermediate, key))), R::kValid));
}

// ---------------------------------------------------------------------------
// Revocation (CRL)
// ---------------------------------------------------------------------------

TEST_F(VerifyCertificatePathTest, RevokedLeafIsRejected)
{
    Input input = BaseInput();
    CrlSpec revoking;
    revoking.revoked_serials = {3};
    WithCrls(input, {MakeCrl(m_root, {}), MakeCrl(m_intermediate, revoking)});
    EXPECT_TRUE(HasResult(VerifyCertificatePath(input), R::kRevoked));
}

TEST_F(VerifyCertificatePathTest, RevokedIntermediateIsRejected)
{
    Input input = BaseInput();
    CrlSpec revoking;
    revoking.revoked_serials = {2};
    WithCrls(input, {MakeCrl(m_root, revoking), MakeCrl(m_intermediate, {})});
    EXPECT_TRUE(HasResult(VerifyCertificatePath(input), R::kRevoked));
}

TEST_F(VerifyCertificatePathTest, RevocationIsIgnoredWhenPolicyIsNone)
{
    Input input = BaseInput();
    CrlSpec revoking;
    revoking.revoked_serials = {3};
    input.crls = {MakeCrl(m_root, {}), MakeCrl(m_intermediate, revoking)};
    EXPECT_TRUE(HasResult(VerifyCertificatePath(input), R::kValid));
}

TEST_F(VerifyCertificatePathTest, MissingCrlFailsClosed)
{
    Input input = BaseInput();
    WithCrls(input, {MakeCrl(m_intermediate, {})});  // nothing from the root for the intermediate
    EXPECT_TRUE(HasResult(VerifyCertificatePath(input), R::kRevocationStatusUnavailable));
}

TEST_F(VerifyCertificatePathTest, MissingCrlIsToleratedWhenBestEffort)
{
    Input input = BaseInput();
    WithCrls(input, {MakeCrl(m_intermediate, {})}, /*best_effort=*/true);
    EXPECT_TRUE(HasResult(VerifyCertificatePath(input), R::kValid));
}

TEST_F(VerifyCertificatePathTest, ExpiredCrlFailsClosed)
{
    Input input = BaseInput();
    CrlSpec stale;
    stale.last_update = kNow - 30 * kDay;
    stale.next_update = kNow - kDay;
    WithCrls(input, {MakeCrl(m_root, {}), MakeCrl(m_intermediate, stale)});
    EXPECT_TRUE(HasResult(VerifyCertificatePath(input), R::kRevocationStatusUnavailable));
}

TEST_F(VerifyCertificatePathTest, NotYetValidCrlFailsClosed)
{
    Input input = BaseInput();
    CrlSpec future;
    future.last_update = kNow + kDay;
    future.next_update = kNow + 7 * kDay;
    WithCrls(input, {MakeCrl(m_root, {}), MakeCrl(m_intermediate, future)});
    EXPECT_TRUE(HasResult(VerifyCertificatePath(input), R::kRevocationStatusUnavailable));
}

TEST_F(VerifyCertificatePathTest, ExpiredCrlListingTheLeafIsNotAcceptedWhenBestEffort)
{
    // A stale CRL still carries positive revocation evidence; best effort must not turn it into kValid.
    Input input = BaseInput();
    CrlSpec stale;
    stale.last_update = kNow - 30 * kDay;
    stale.next_update = kNow - kDay;
    stale.revoked_serials = {3};
    WithCrls(input, {MakeCrl(m_root, {}), MakeCrl(m_intermediate, stale)}, /*best_effort=*/true);
    EXPECT_TRUE(IsRejected(VerifyCertificatePath(input)));
}

TEST_F(VerifyCertificatePathTest, CrlWithForgedSignatureFailsClosed)
{
    Input input = BaseInput();
    WithCrls(input, {MakeCrl(m_root, {}), MakeCrl(m_intermediate, {}, NewKey())});
    EXPECT_TRUE(HasResult(VerifyCertificatePath(input), R::kRevocationStatusUnavailable));
}

TEST_F(VerifyCertificatePathTest, ForgedCrlWithHigherNumberDoesNotHideRevocation)
{
    // The genuine CRL #1 revokes the leaf. A forged CRL in the issuer's name with a higher number and no
    // entries must not displace it, under either coverage policy.
    for (const bool best_effort : {false, true})
    {
        SCOPED_TRACE(best_effort ? "best effort" : "fail closed");
        Input input = BaseInput();
        CrlSpec genuine;
        genuine.crl_number = 1;
        genuine.revoked_serials = {3};
        CrlSpec forged;
        forged.crl_number = 99;
        WithCrls(input,
                 {MakeCrl(m_root, {}), MakeCrl(m_intermediate, genuine), MakeCrl(m_intermediate, forged, NewKey())},
                 best_effort);
        EXPECT_TRUE(HasResult(VerifyCertificatePath(input), R::kRevoked));
    }
}

TEST_F(VerifyCertificatePathTest, UnparseableCrlIsIgnoredAndCoverageStillApplies)
{
    Input input = BaseInput();
    auto junk = std::make_shared<CrlData>();
    junk->bytes = {0x30, 0x03, 0x02, 0x01, 0x00};
    WithCrls(input, {MakeCrl(m_root, {}), junk, nullptr});
    EXPECT_TRUE(HasResult(VerifyCertificatePath(input), R::kRevocationStatusUnavailable));
}

TEST_F(VerifyCertificatePathTest, OcspPoliciesAreUnsupported)
{
    for (const auto policy :
         {::score::crypto::RevocationCheckPolicy::kOcspOnly, ::score::crypto::RevocationCheckPolicy::kOcspWithCrlFallback})
    {
        Input input = BaseInput();
        input.revocation_policy = static_cast<std::uint8_t>(policy);
        const auto res = VerifyCertificatePath(input);
        ASSERT_FALSE(res.has_value());
        EXPECT_EQ(res.error(), Error::kUnsupportedOperation);
    }
}

TEST_F(VerifyCertificatePathTest, UnknownRevocationPolicyValueIsRejected)
{
    Input input = BaseInput();
    input.revocation_policy = 0x7FU;
    const auto res = VerifyCertificatePath(input);
    EXPECT_TRUE(IsRejected(res));
    ASSERT_FALSE(res.has_value());
    EXPECT_EQ(res.error(), Error::kInvalidArgument);
}

// ---------------------------------------------------------------------------
// Malformed inputs
// ---------------------------------------------------------------------------

TEST_F(VerifyCertificatePathTest, MissingLeafIsInvalidArgument)
{
    Input input = BaseInput();
    input.leaf = nullptr;
    const auto res = VerifyCertificatePath(input);
    ASSERT_FALSE(res.has_value());
    EXPECT_EQ(res.error(), Error::kInvalidArgument);
}

TEST_F(VerifyCertificatePathTest, UnparseableLeafIsParsingError)
{
    Input input = BaseInput();
    input.leaf = std::make_shared<cert_management_types>(::score::crypto::daemon::cert_management::CertChainMetadata{},
                                                         std::vector<std::uint8_t>{0x30, 0x00},
                                                         ::score::crypto::FormatType::kDer);
    const auto res = VerifyCertificatePath(input);
    ASSERT_FALSE(res.has_value());
    EXPECT_EQ(res.error(), Error::kCertificateParsingFailed);
}

TEST_F(VerifyCertificatePathTest, NullAndUnparseableIntermediatesAndAnchorsAreSkipped)
{
    Input input = BaseInput();
    auto junk = std::make_shared<cert_management_types>(::score::crypto::daemon::cert_management::CertChainMetadata{},
                                                        std::vector<std::uint8_t>{0x01, 0x02},
                                                        ::score::crypto::FormatType::kDer);
    input.chain.insert(input.chain.begin(), {nullptr, junk});
    input.additional = {nullptr, junk};
    input.trusted.insert(input.trusted.begin(), {nullptr, junk});
    EXPECT_TRUE(HasResult(VerifyCertificatePath(input), R::kValid));
}

TEST_F(VerifyCertificatePathTest, OnlyUnparseableAnchorsIsRejected)
{
    Input input = BaseInput();
    input.trusted = {std::make_shared<cert_management_types>(::score::crypto::daemon::cert_management::CertChainMetadata{},
                                                             std::vector<std::uint8_t>{0x01},
                                                             ::score::crypto::FormatType::kDer)};
    EXPECT_TRUE(IsRejected(VerifyCertificatePath(input)));
}

}  // namespace
}  // namespace score::crypto::daemon::provider::score_provider::openssl::handler
