<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\X509\Regression;

use Iterator;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\RequiresPhpExtension;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Type\Constructed\Sequence;
use SpomkyLabs\Pki\ASN1\Type\Primitive\NullType;
use SpomkyLabs\Pki\ASN1\Type\Primitive\ObjectIdentifier;
use SpomkyLabs\Pki\CryptoEncoding\PEM;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\AlgorithmIdentifier;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Asymmetric\RSAEncryptionAlgorithmIdentifier;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Asymmetric\RSAPSSSSAEncryptionAlgorithmIdentifier;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Hash\SHA256AlgorithmIdentifier;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Hash\SHA512AlgorithmIdentifier;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Signature\RSASSAPSSAlgorithmIdentifier;
use SpomkyLabs\Pki\CryptoTypes\Asymmetric\PrivateKey;
use SpomkyLabs\Pki\CryptoTypes\Asymmetric\PrivateKeyInfo;
use SpomkyLabs\Pki\CryptoTypes\Asymmetric\PublicKey;
use SpomkyLabs\Pki\CryptoTypes\Asymmetric\PublicKeyInfo;
use SpomkyLabs\Pki\CryptoTypes\Asymmetric\RSA\RSAPublicKey;
use SpomkyLabs\Pki\CryptoTypes\Asymmetric\RSA\RSASSAPSSPrivateKey;
use SpomkyLabs\Pki\X501\ASN1\Name;
use SpomkyLabs\Pki\X509\AttributeCertificate\AttCertIssuer;
use SpomkyLabs\Pki\X509\AttributeCertificate\AttCertValidityPeriod;
use SpomkyLabs\Pki\X509\AttributeCertificate\Attribute\RoleAttributeValue;
use SpomkyLabs\Pki\X509\AttributeCertificate\AttributeCertificate;
use SpomkyLabs\Pki\X509\AttributeCertificate\AttributeCertificateInfo;
use SpomkyLabs\Pki\X509\AttributeCertificate\Attributes;
use SpomkyLabs\Pki\X509\AttributeCertificate\Holder;
use SpomkyLabs\Pki\X509\AttributeCertificate\IssuerSerial;
use SpomkyLabs\Pki\X509\Certificate\Certificate;
use SpomkyLabs\Pki\X509\Certificate\TBSCertificate;
use SpomkyLabs\Pki\X509\Certificate\Validity;
use SpomkyLabs\Pki\X509\CertificationPath\CertificationPath;
use SpomkyLabs\Pki\X509\CertificationPath\Exception\PathValidationException;
use SpomkyLabs\Pki\X509\CertificationPath\PathValidation\PathValidationConfig;
use SpomkyLabs\Pki\X509\CertificationPath\PathValidation\PathValidationResult;
use SpomkyLabs\Pki\X509\CertificationRequest\CertificationRequest;
use SpomkyLabs\Pki\X509\CertificationRequest\CertificationRequestInfo;
use function sprintf;
use UnexpectedValueException;

/**
 * Certificates, certification requests and certification paths signed with RSASSA-PSS.
 *
 * A PSS signed certificate was refused when it was parsed: the OID was not mapped to a signature algorithm, and
 * the PSS key algorithm identifier only accepted NULL parameters.
 *
 * The fixtures in tests/assets/rsassa-pss were generated with OpenSSL 3.6:
 *
 *     openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out rsa-key.pem
 *     openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:1025 -out rsa-1025-key.pem
 *     openssl genpkey -algorithm RSA-PSS -pkeyopt rsa_keygen_bits:2048 -out pss-key.pem
 *     openssl genpkey -algorithm RSA-PSS -pkeyopt rsa_keygen_bits:2048 -pkeyopt rsa_pss_keygen_md:sha256 \
 *         -pkeyopt rsa_pss_keygen_mgf1_md:sha256 -pkeyopt rsa_pss_keygen_saltlen:32 -out pss-sha256-key.pem
 *     openssl req -new -x509 -key rsa-key.pem -subj /CN=pss-sha256 -days 36500 -sha256 \
 *         -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:32 -out sha256-salt32.pem
 *     openssl req -new -x509 -key rsa-key.pem -subj /CN=pss-sha384 -days 36500 -sha384 \
 *         -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:digest -out sha384.pem
 *     openssl req -new -x509 -key rsa-key.pem -subj /CN=pss-sha512 -days 36500 -sha512 \
 *         -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:64 -out sha512-salt64.pem
 *     openssl req -new -x509 -key rsa-key.pem -subj /CN=pss-sha224 -days 36500 -sha224 \
 *         -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:digest -out sha224.pem
 *     openssl req -new -x509 -key rsa-key.pem -subj /CN=pss-default -days 36500 -sha1 \
 *         -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:20 -out default-params.pem
 *     openssl req -new -x509 -key rsa-1025-key.pem -subj /CN=pss-1025 -days 36500 -sha256 \
 *         -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:32 -out rsa-1025.pem
 *     openssl req -new -x509 -key pss-key.pem -subj /CN=pss-key -days 36500 -sha256 \
 *         -sigopt rsa_pss_saltlen:32 -out pss-key-cert.pem
 *     openssl req -new -x509 -key pss-sha256-key.pem -subj /CN=pss-restricted-key -days 36500 -sha256 \
 *         -out pss-sha256-key-cert.pem
 *     openssl req -new -key rsa-key.pem -subj /CN=pss-csr -sha256 -sigopt rsa_padding_mode:pss \
 *         -sigopt rsa_pss_saltlen:32 -out csr.pem
 *     openssl req -new -x509 -key pss-sha256-key.pem -subj /CN=pss-root -days 36500 -sha256 \
 *         -addext basicConstraints=critical,CA:true -addext keyUsage=critical,keyCertSign,cRLSign \
 *         -out chain-root.pem
 *     openssl req -new -key rsa-key.pem -subj /CN=pss-leaf -out leaf.csr
 *     openssl x509 -req -in leaf.csr -CA chain-root.pem -CAkey pss-sha256-key.pem -set_serial 2 -days 36500 \
 *         -sha256 -sigopt rsa_pss_saltlen:32 -out chain-leaf.pem
 *
 * OpenSSL does not give every odd size asked for: the 1025 bit key, whose encoded message is a byte shorter than
 * the modulus, was checked with `openssl pkey -noout -text`. reproducer-cert.pem is the self-signed certificate
 * the issue was reported with.
 *
 * @internal
 */
#[RequiresPhpExtension('openssl')]
final class RSASSAPSSSignatureTest extends TestCase
{
    /**
     * @return Iterator<string, array{string, string}>
     */
    public static function certificateProvider(): Iterator
    {
        yield 'SHA-256 salt 32' => ['sha256-salt32.pem', 'sha256-salt32.pem'];
        yield 'SHA-224' => ['sha224.pem', 'sha224.pem'];
        yield 'SHA-384' => ['sha384.pem', 'sha384.pem'];
        yield 'SHA-512 salt 64' => ['sha512-salt64.pem', 'sha512-salt64.pem'];
        yield 'default parameters' => ['default-params.pem', 'default-params.pem'];
        yield '1025 bit key' => ['rsa-1025.pem', 'rsa-1025.pem'];
        yield 'key restricted to PSS without parameters' => ['pss-key-cert.pem', 'pss-key-cert.pem'];
        yield 'key restricted to PSS with parameters' => ['pss-sha256-key-cert.pem', 'pss-sha256-key-cert.pem'];
        yield 'chain root' => ['chain-root.pem', 'chain-root.pem'];
        yield 'chain leaf' => ['chain-leaf.pem', 'chain-root.pem'];
        yield 'reproducer' => ['reproducer-cert.pem', 'reproducer-cert.pem'];
    }

    #[Test]
    #[DataProvider('certificateProvider')]
    public function certificateDecodesAndReEncodesUnchanged(string $file, string $issuer): void
    {
        $pem = self::pem($file);
        $cert = Certificate::fromPEM($pem);

        static::assertInstanceOf(RSASSAPSSAlgorithmIdentifier::class, $cert->signatureAlgorithm());
        static::assertInstanceOf(RSASSAPSSAlgorithmIdentifier::class, $cert->tbsCertificate()->signature());
        static::assertTrue($cert->signatureAlgorithm()->hasParameters());
        static::assertSame($pem->data(), $cert->toDER());
        static::assertSame($pem->data(), Certificate::fromDER($cert->toDER())->toDER());
    }

    #[Test]
    #[DataProvider('certificateProvider')]
    public function certificateVerifies(string $file, string $issuer): void
    {
        $cert = self::certificate($file);
        $key = self::certificate($issuer)->tbsCertificate()->subjectPublicKeyInfo();

        $other = $file === 'rsa-1025.pem' ? 'pss-key-cert.pem' : 'rsa-1025.pem';

        static::assertTrue($cert->verify($key));
        static::assertFalse($cert->verify(self::certificate($other)->tbsCertificate()->subjectPublicKeyInfo()));
    }

    #[Test]
    public function reEncodedCertificateVerifies(): void
    {
        // a certificate re-encoded from its decoded form, rather than from the bytes received, must verify too:
        // the PSS parameters are kept as OpenSSL encoded them, with NULL hash parameters
        $cert = self::certificate('reproducer-cert.pem');
        $copy = Certificate::create($cert->tbsCertificate(), $cert->signatureAlgorithm(), $cert->signatureValue());

        static::assertTrue($copy->verify($cert->tbsCertificate()->subjectPublicKeyInfo()));
    }

    #[Test]
    public function certificateParametersAreRead(): void
    {
        $algo = self::certificate('sha512-salt64.pem')->signatureAlgorithm();

        static::assertInstanceOf(RSASSAPSSAlgorithmIdentifier::class, $algo);
        static::assertSame(AlgorithmIdentifier::OID_SHA512, $algo->hashAlgorithm()->oid());
        static::assertSame(AlgorithmIdentifier::OID_MGF1, $algo->maskGenAlgorithm()->oid());
        static::assertSame(AlgorithmIdentifier::OID_SHA512, $algo->maskGenHashAlgorithm()?->oid());
        static::assertSame(64, $algo->saltLength());
        static::assertSame(1, $algo->trailerField());
    }

    #[Test]
    public function certificationRequestDecodesReEncodesAndVerifies(): void
    {
        $pem = self::pem('csr.pem');
        $csr = CertificationRequest::fromPEM($pem);

        static::assertInstanceOf(RSASSAPSSAlgorithmIdentifier::class, $csr->signatureAlgorithm());
        static::assertSame($pem->data(), $csr->toDER());
        static::assertTrue($csr->verify());
    }

    #[Test]
    public function chainValidates(): void
    {
        $root = self::certificate('chain-root.pem');
        $leaf = self::certificate('chain-leaf.pem');

        static::assertInstanceOf(
            PathValidationResult::class,
            CertificationPath::create($root, $leaf)->validate(PathValidationConfig::defaultConfig())
        );
        static::assertInstanceOf(
            PathValidationResult::class,
            CertificationPath::create($root, $leaf)->validate(
                PathValidationConfig::defaultConfig()->withAllowedSignatureAlgorithms(
                    ...PathValidationConfig::HARDENED_ALLOWED_SIGNATURE_ALGORITHMS
                )
            )
        );
    }

    #[Test]
    public function chainIsRefusedWhenPSSIsNotAllowed(): void
    {
        $config = PathValidationConfig::defaultConfig()
            ->withAllowedSignatureAlgorithms(AlgorithmIdentifier::OID_SHA256_WITH_RSA_ENCRYPTION);

        $this->expectException(PathValidationException::class);
        CertificationPath::create(self::certificate('chain-root.pem'), self::certificate('chain-leaf.pem'))
            ->validate($config);
    }

    #[Test]
    public function minimumKeySizeAppliesToAKeyRestrictedToPSS(): void
    {
        $config = PathValidationConfig::defaultConfig()->withMinimumRSAKeySize(2049);

        $this->expectException(PathValidationException::class);
        $this->expectExceptionMessage('2048');
        CertificationPath::create(self::certificate('chain-root.pem'), self::certificate('chain-leaf.pem'))
            ->validate($config);
    }

    #[Test]
    public function pssOverSHA1IsAllowedWhereSHA1Is(): void
    {
        $cert = self::certificate('default-params.pem');

        static::assertInstanceOf(
            PathValidationResult::class,
            CertificationPath::create($cert)->validate(PathValidationConfig::defaultConfig())
        );
    }

    #[Test]
    public function pssOverSHA1IsRefusedWhereSHA1IsNot(): void
    {
        $config = PathValidationConfig::defaultConfig()
            ->withAllowedSignatureAlgorithms(...PathValidationConfig::HARDENED_ALLOWED_SIGNATURE_ALGORITHMS);

        $this->expectException(PathValidationException::class);
        CertificationPath::create(self::certificate('default-params.pem'))->validate($config);
    }

    #[Test]
    public function outerParametersMustMatchTheSignedOnes(): void
    {
        // the outer signatureAlgorithm is not signed: with only the OID compared, its PSS parameters would decide
        // alone how the signature is checked
        $seq = Sequence::fromDER(self::pem('sha256-salt32.pem')->data());
        $seq = $seq->withReplaced(
            1,
            RSASSAPSSAlgorithmIdentifier::create(SHA256AlgorithmIdentifier::create(), null, 31)->toASN1()
        );

        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessage('Signature algorithm parameters do not match the parameters of the tbsCertificate.');
        Certificate::fromASN1($seq);
    }

    #[Test]
    public function outerParametersMustBeEncodedLikeTheSignedOnes(): void
    {
        // the same parameters, but without the NULL hash parameters OpenSSL writes: RFC 5280 asks for the same
        // algorithm identifier, which OpenSSL compares byte for byte
        $seq = Sequence::fromDER(self::pem('sha256-salt32.pem')->data());
        $seq = $seq->withReplaced(
            1,
            RSASSAPSSAlgorithmIdentifier::create(SHA256AlgorithmIdentifier::create())->toASN1()
        );

        $this->expectException(UnexpectedValueException::class);
        Certificate::fromASN1($seq);
    }

    #[Test]
    public function attributeCertificateOuterParametersMustMatchTheSignedOnes(): void
    {
        $key = self::privateKey('rsa-key.pem');
        $holder = self::certificate('chain-leaf.pem');
        $ac = AttributeCertificateInfo::create(
            Holder::create(IssuerSerial::fromPKC($holder)),
            AttCertIssuer::fromPKC($holder),
            AttCertValidityPeriod::fromStrings('2025-01-01 12:00:00 UTC', '2035-01-01 12:00:00 UTC'),
            Attributes::fromAttributeValues(RoleAttributeValue::fromString('urn:administrator'))
        )
            ->withSerialNumber(1)
            ->sign(RSASSAPSSAlgorithmIdentifier::create(SHA256AlgorithmIdentifier::create()), $key);
        $seq = $ac->toASN1();

        static::assertTrue(AttributeCertificate::fromASN1($seq)->verify($holder->tbsCertificate()->subjectPublicKeyInfo()));

        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessage('Signature algorithm parameters do not match the parameters of the acinfo.');
        AttributeCertificate::fromASN1(
            $seq->withReplaced(
                1,
                RSASSAPSSAlgorithmIdentifier::create(SHA256AlgorithmIdentifier::create(), null, 0)->toASN1()
            )
        );
    }

    /**
     * @return Iterator<string, array{string, RSASSAPSSAlgorithmIdentifier}>
     */
    public static function signerProvider(): Iterator
    {
        yield 'RSA key, SHA-256' => ['rsa-key.pem', RSASSAPSSAlgorithmIdentifier::create(SHA256AlgorithmIdentifier::create())];
        yield 'RSA key, SHA-512 salt 64' => [
            'rsa-key.pem',
            RSASSAPSSAlgorithmIdentifier::create(SHA512AlgorithmIdentifier::create(), null, 64),
        ];
        yield 'RSA key, default parameters' => ['rsa-key.pem', RSASSAPSSAlgorithmIdentifier::create()];
        yield '1025 bit key' => ['rsa-1025-key.pem', RSASSAPSSAlgorithmIdentifier::create(SHA256AlgorithmIdentifier::create())];
        yield 'key restricted to PSS' => ['pss-key.pem', RSASSAPSSAlgorithmIdentifier::create(SHA256AlgorithmIdentifier::create())];
        yield 'key restricted to PSS with parameters' => [
            'pss-sha256-key.pem',
            RSASSAPSSAlgorithmIdentifier::create(SHA256AlgorithmIdentifier::create()),
        ];
    }

    #[Test]
    #[DataProvider('signerProvider')]
    public function openSSLVerifiesASignedCertificate(string $keyFile, RSASSAPSSAlgorithmIdentifier $algo): void
    {
        $key = self::privateKey($keyFile);
        $subject = Name::fromString('cn=Library signed');
        // a key restricted to PSS keeps its SubjectPublicKeyInfo, so that OpenSSL enforces the restrictions
        $cert = TBSCertificate::create(
            $subject,
            $key->publicKeyInfo(),
            $subject,
            Validity::fromStrings('now - 1 hour', 'now + 1 hour')
        )
            ->withSerialNumber('1')
            ->sign($algo, $key);

        static::assertTrue($cert->verify($cert->tbsCertificate()->subjectPublicKeyInfo()));
        static::assertSame(
            1,
            openssl_x509_verify((string) $cert->toPEM(), (string) $cert->tbsCertificate()->subjectPublicKeyInfo()->toPEM())
        );
    }

    /**
     * @return Iterator<string, array{RSASSAPSSAlgorithmIdentifier}>
     */
    public static function forbiddenBySHA256KeyProvider(): Iterator
    {
        yield 'a 20 byte salt' => [RSASSAPSSAlgorithmIdentifier::create(SHA256AlgorithmIdentifier::create(), null, 20)];
        yield 'SHA-512' => [RSASSAPSSAlgorithmIdentifier::create(SHA512AlgorithmIdentifier::create())];
    }

    #[Test]
    #[DataProvider('forbiddenBySHA256KeyProvider')]
    public function aSignatureTheKeyRestrictionsForbidIsRefusedAsByOpenSSL(
        RSASSAPSSAlgorithmIdentifier $algo
    ): void {
        // pss-sha256-key.pem permits SHA-256 with a salt of at least 32 bytes only; the same key material without
        // the restrictions signs anyway
        $unrestricted = PrivateKeyInfo::create(
            RSAEncryptionAlgorithmIdentifier::create(),
            self::privateKey('pss-sha256-key.pem')->privateKeyData()
        );
        $spki = self::spki('pss-sha256-key.pem');
        static::assertNotNull($spki);
        $subject = Name::fromString('cn=Forbidden parameters');
        $cert = TBSCertificate::create($subject, $spki, $subject, Validity::fromStrings('now - 1 hour', 'now + 1 hour'))
            ->withSerialNumber('1')
            ->sign($algo, $unrestricted);

        static::assertTrue($cert->verify($unrestricted->publicKeyInfo()));
        static::assertFalse($cert->verify($spki));
        static::assertNotSame(1, @openssl_x509_verify((string) $cert->toPEM(), (string) $spki->toPEM()));
        while (openssl_error_string() !== false) {
            // drain the errors of the refused verification
        }
    }

    #[Test]
    #[DataProvider('signerProvider')]
    public function openSSLVerifiesASignedCertificationRequest(string $keyFile, RSASSAPSSAlgorithmIdentifier $algo): void
    {
        $key = self::privateKey($keyFile);
        $csr = CertificationRequestInfo::create(
            Name::fromString('cn=Library signed'),
            $key->publicKeyInfo()
        )->sign($algo, $key);

        static::assertTrue($csr->verify());
        static::assertNotFalse(openssl_csr_get_public_key((string) $csr->toPEM()));

        $file = tempnam(sys_get_temp_dir(), 'pki-pss-');
        static::assertIsString($file);
        try {
            file_put_contents($file, (string) $csr->toPEM());
            exec(sprintf('openssl req -in %s -verify -noout 2>&1', escapeshellarg($file)), $output, $status);
        } finally {
            unlink($file);
        }
        if ($status === 127) {
            static::markTestSkipped('The openssl command is not available.');
        }
        static::assertSame(0, $status, implode("\n", $output));
    }

    #[Test]
    public function aPublicKeyRestrictedToPSSIsAnRSAKey(): void
    {
        foreach (['pss-key-cert.pem', 'pss-sha256-key-cert.pem'] as $file) {
            $spki = self::certificate($file)->tbsCertificate()->subjectPublicKeyInfo();

            static::assertInstanceOf(RSASSAPSSAlgorithmIdentifier::class, $spki->algorithmIdentifier());
            static::assertInstanceOf(RSAPublicKey::class, $spki->publicKey());
            static::assertInstanceOf(RSAPublicKey::class, PublicKey::fromPEM($spki->toPEM()));
            static::assertInstanceOf(RSAPublicKey::class, RSAPublicKey::fromPEM($spki->toPEM()));
        }
        $spki = self::certificate('pss-key-cert.pem')->tbsCertificate()->subjectPublicKeyInfo();
        static::assertFalse(self::pssAlgorithm($spki)->hasParameters());
        $spki = self::certificate('pss-sha256-key-cert.pem')->tbsCertificate()->subjectPublicKeyInfo();
        static::assertTrue(self::pssAlgorithm($spki)->hasParameters());
        static::assertSame(32, self::pssAlgorithm($spki)->saltLength());
    }

    #[Test]
    public function aPublicKeyWithNullPSSParametersIsAnRSAKey(): void
    {
        $spki = self::certificate('pss-key-cert.pem')->tbsCertificate()->subjectPublicKeyInfo();
        $der = Sequence::create(
            Sequence::create(ObjectIdentifier::create(AlgorithmIdentifier::OID_RSASSA_PSS_ENCRYPTION), NullType::create()),
            $spki->publicKeyData()
        )->toDER();
        $decoded = PublicKeyInfo::fromDER($der);

        static::assertInstanceOf(RSAPublicKey::class, $decoded->publicKey());
        static::assertSame($der, $decoded->toDER());
    }

    #[Test]
    public function aPrivateKeyRestrictedToPSSIsAnRSAKey(): void
    {
        foreach (['pss-key.pem', 'pss-sha256-key.pem'] as $file) {
            $pem = self::pem($file);
            $info = PrivateKeyInfo::fromPEM($pem);

            static::assertInstanceOf(RSASSAPSSAlgorithmIdentifier::class, $info->algorithmIdentifier());
            static::assertSame($pem->data(), $info->toDER());
            $key = $info->privateKey();
            static::assertInstanceOf(RSASSAPSSPrivateKey::class, $key);
            static::assertInstanceOf(RSAPublicKey::class, $key->publicKey());
            static::assertInstanceOf(RSASSAPSSPrivateKey::class, PrivateKey::fromPEM($pem));
        }
    }

    /**
     * @return Iterator<string, array{string, string}>
     */
    public static function restrictedKeyProvider(): Iterator
    {
        yield 'without parameters' => ['pss-key.pem', 'pss-key-cert.pem'];
        yield 'with parameters' => ['pss-sha256-key.pem', 'pss-sha256-key-cert.pem'];
    }

    #[Test]
    #[DataProvider('restrictedKeyProvider')]
    public function aPrivateKeyRestrictedToPSSKeepsItsRestrictions(string $keyFile, string $certFile): void
    {
        $pem = self::pem($keyFile);
        $key = PrivateKeyInfo::fromPEM($pem)->privateKey();
        static::assertInstanceOf(RSASSAPSSPrivateKey::class, $key);
        $spki = self::certificate($certFile)->tbsCertificate()->subjectPublicKeyInfo();

        static::assertSame($pem->data(), PrivateKeyInfo::fromPrivateKey($key)->toDER());
        static::assertSame($pem->data(), PrivateKeyInfo::fromPrivateKey(PrivateKey::fromPEM($pem))->toDER());
        // the SubjectPublicKeyInfo OpenSSL wrote in the certificate
        static::assertSame($spki->toDER(), $key->publicKey()->publicKeyInfo()->toDER());
        static::assertSame($spki->toDER(), PrivateKeyInfo::fromPEM($pem)->publicKeyInfo()->toDER());
    }

    #[Test]
    #[DataProvider('restrictedKeyProvider')]
    public function aPublicKeyRestrictedToPSSKeepsItsRestrictions(string $keyFile, string $certFile): void
    {
        $spki = self::certificate($certFile)->tbsCertificate()->subjectPublicKeyInfo();

        static::assertSame($spki->toDER(), $spki->publicKey()->publicKeyInfo()->toDER());
        static::assertSame($spki->toDER(), PublicKey::fromPEM($spki->toPEM())->publicKeyInfo()->toDER());
        static::assertSame($spki->toDER(), RSAPublicKey::fromPEM($spki->toPEM())->publicKeyInfo()->toDER());
    }

    #[Test]
    public function aConvertedKeyStillRefusesWhatItsRestrictionsForbid(): void
    {
        $restricted = self::privateKey('pss-sha256-key.pem');
        $unrestricted = PrivateKeyInfo::create(RSAEncryptionAlgorithmIdentifier::create(), $restricted->privateKeyData());
        $algo = RSASSAPSSAlgorithmIdentifier::create(SHA256AlgorithmIdentifier::create(), null, 20);
        $subject = Name::fromString('cn=Forbidden parameters');
        $cert = TBSCertificate::create(
            $subject,
            $unrestricted->publicKeyInfo(),
            $subject,
            Validity::fromStrings('now - 1 hour', 'now + 1 hour')
        )
            ->withSerialNumber('1')
            ->sign($algo, $unrestricted);
        $spki = self::certificate('pss-sha256-key-cert.pem')->tbsCertificate()->subjectPublicKeyInfo();

        static::assertFalse($cert->verify($spki->publicKey()->publicKeyInfo()));
        static::assertFalse($cert->verify($restricted->publicKeyInfo()));

        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessage('RSASSA-PSS parameters are not permitted by the restrictions of the key.');
        TBSCertificate::create($subject, $spki, $subject, Validity::fromStrings('now - 1 hour', 'now + 1 hour'))
            ->withSerialNumber('1')
            ->sign($algo, PrivateKeyInfo::fromPrivateKey($restricted->privateKey()));
    }

    #[Test]
    public function anRSAKeyKeepsRSAEncryption(): void
    {
        $key = self::privateKey('rsa-key.pem')->publicKeyInfo();

        static::assertInstanceOf(RSAEncryptionAlgorithmIdentifier::class, $key->publicKey()->algorithmIdentifier());
        static::assertInstanceOf(
            RSAEncryptionAlgorithmIdentifier::class,
            RSAPublicKey::fromPEM($key->toPEM())->algorithmIdentifier()
        );
        $rsa = RSAPublicKey::fromDER($key->publicKeyData()->string());
        static::assertInstanceOf(RSAEncryptionAlgorithmIdentifier::class, $rsa->algorithmIdentifier());
        static::assertSame(
            $key->toDER(),
            $rsa->withAlgorithmIdentifier(RSAEncryptionAlgorithmIdentifier::create())->publicKeyInfo()->toDER()
        );
    }

    #[Test]
    public function aPSSKeyCreatedWithoutAnAlgorithmIsUnchanged(): void
    {
        $key = PrivateKeyInfo::fromPEM(self::pem('pss-key.pem'))->privateKey();
        static::assertInstanceOf(RSASSAPSSPrivateKey::class, $key);
        $bare = RSASSAPSSPrivateKey::fromDER($key->toDER());

        static::assertInstanceOf(RSAPSSSSAEncryptionAlgorithmIdentifier::class, $bare->algorithmIdentifier());
        static::assertInstanceOf(
            RSAEncryptionAlgorithmIdentifier::class,
            $bare->publicKey()
                ->algorithmIdentifier()
        );
    }

    #[Test]
    public function anRSAPublicKeyRefusesAnAlgorithmOfAnotherKeyType(): void
    {
        $key = self::privateKey('rsa-key.pem')->publicKeyInfo()->publicKey();
        static::assertInstanceOf(RSAPublicKey::class, $key);

        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessage('Algorithm ecPublicKey is not an RSA key algorithm.');
        $key->withAlgorithmIdentifier(
            PublicKeyInfo::fromPEM(PEM::fromFile(TEST_ASSETS_DIR . '/ec/public_key.pem'))->algorithmIdentifier()
        );
    }

    #[Test]
    public function aPSSPrivateKeyRefusesAnotherAlgorithm(): void
    {
        $key = PrivateKeyInfo::fromPEM(self::pem('pss-key.pem'))->privateKey();
        static::assertInstanceOf(RSASSAPSSPrivateKey::class, $key);

        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessage('Algorithm rsaEncryption is not RSASSA-PSS.');
        $key->withAlgorithmIdentifier(RSAEncryptionAlgorithmIdentifier::create());
    }

    #[Test]
    public function rsaEncryptionKeysAreStillRSAKeys(): void
    {
        $info = self::privateKey('rsa-key.pem');

        static::assertInstanceOf(RSAEncryptionAlgorithmIdentifier::class, $info->algorithmIdentifier());
        static::assertInstanceOf(RSAPublicKey::class, $info->publicKeyInfo()->publicKey());
    }

    private static function pem(string $file): PEM
    {
        return PEM::fromFile(TEST_ASSETS_DIR . '/rsassa-pss/' . $file);
    }

    private static function certificate(string $file): Certificate
    {
        return Certificate::fromPEM(self::pem($file));
    }

    private static function privateKey(string $file): PrivateKeyInfo
    {
        return PrivateKeyInfo::fromPEM(self::pem($file));
    }

    /**
     * The SubjectPublicKeyInfo OpenSSL wrote for a key restricted to PSS, null for another key.
     */
    private static function spki(string $keyFile): ?PublicKeyInfo
    {
        return match ($keyFile) {
            'pss-key.pem' => self::certificate('pss-key-cert.pem')->tbsCertificate()->subjectPublicKeyInfo(),
            'pss-sha256-key.pem' => self::certificate('pss-sha256-key-cert.pem')->tbsCertificate()->subjectPublicKeyInfo(),
            default => null,
        };
    }

    private static function pssAlgorithm(PublicKeyInfo $spki): RSASSAPSSAlgorithmIdentifier
    {
        $algo = $spki->algorithmIdentifier();
        static::assertInstanceOf(RSASSAPSSAlgorithmIdentifier::class, $algo);

        return $algo;
    }
}
