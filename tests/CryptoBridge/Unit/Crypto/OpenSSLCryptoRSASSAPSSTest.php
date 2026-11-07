<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\CryptoBridge\Unit\Crypto;

use function chr;
use Iterator;
use const OPENSSL_NO_PADDING;
use function ord;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\RequiresPhpExtension;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Type\Constructed\Sequence;
use SpomkyLabs\Pki\CryptoBridge\Crypto\OpenSSLCrypto;
use SpomkyLabs\Pki\CryptoEncoding\PEM;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\AlgorithmIdentifier;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Hash\SHA1AlgorithmIdentifier;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Hash\SHA224AlgorithmIdentifier;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Hash\SHA256AlgorithmIdentifier;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Hash\SHA384AlgorithmIdentifier;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Hash\SHA512AlgorithmIdentifier;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Signature\RSASSAPSSAlgorithmIdentifier;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Signature\SHA256WithRSAEncryptionAlgorithmIdentifier;
use SpomkyLabs\Pki\CryptoTypes\Asymmetric\PrivateKeyInfo;
use SpomkyLabs\Pki\CryptoTypes\Asymmetric\PublicKeyInfo;
use SpomkyLabs\Pki\CryptoTypes\Signature\RSASignature;
use SpomkyLabs\Pki\CryptoTypes\Signature\Signature;
use SpomkyLabs\Pki\X509\Certificate\Certificate;
use const STR_PAD_LEFT;
use UnexpectedValueException;

/**
 * RSASSA-PSS signing and verification by OpenSSLCrypto.
 *
 * The keys and certificates are under tests/assets/rsassa-pss; RSASSAPSSSignatureTest documents how they were
 * generated. Encoded messages that are wrong in one precise way are built here and put through the raw RSA
 * private key operation, so that every check of EMSA-PSS-VERIFY is reached.
 *
 * @internal
 */
#[RequiresPhpExtension('openssl')]
final class OpenSSLCryptoRSASSAPSSTest extends TestCase
{
    private const DATA = 'PAYLOAD';

    /**
     * @return Iterator<string, array{string, RSASSAPSSAlgorithmIdentifier}>
     */
    public static function signProvider(): Iterator
    {
        $keys = ['rsa-key.pem', 'pss-key.pem', 'pss-sha256-key.pem', 'rsa-1025-key.pem'];
        $algos = [
            'defaults' => RSASSAPSSAlgorithmIdentifier::create(),
            'SHA-224' => RSASSAPSSAlgorithmIdentifier::create(SHA224AlgorithmIdentifier::create()),
            'SHA-256' => RSASSAPSSAlgorithmIdentifier::create(SHA256AlgorithmIdentifier::create()),
            'SHA-384' => RSASSAPSSAlgorithmIdentifier::create(SHA384AlgorithmIdentifier::create()),
            'SHA-512 salt 64' => RSASSAPSSAlgorithmIdentifier::create(SHA512AlgorithmIdentifier::create(), null, 64),
            'SHA-256 MGF1 SHA-1' => RSASSAPSSAlgorithmIdentifier::create(
                SHA256AlgorithmIdentifier::create(),
                SHA1AlgorithmIdentifier::create()
            ),
            'SHA-256 no salt' => RSASSAPSSAlgorithmIdentifier::create(SHA256AlgorithmIdentifier::create(), null, 0),
        ];
        foreach ($keys as $key) {
            foreach ($algos as $name => $algo) {
                // 1025 bits leave 128 bytes of encoded message, two short of a SHA-512 hash and a 64 byte salt
                if ($key === 'rsa-1025-key.pem' && $name === 'SHA-512 salt 64') {
                    continue;
                }
                // that key permits SHA-256 with a salt of at least 32 bytes only, see keyRestrictionProvider()
                if ($key === 'pss-sha256-key.pem' && $name !== 'SHA-256') {
                    continue;
                }
                yield "{$key} {$name}" => [$key, $algo];
            }
        }
    }

    #[Test]
    #[DataProvider('signProvider')]
    public function signAndVerify(string $keyFile, RSASSAPSSAlgorithmIdentifier $algo): void
    {
        $key = self::privateKey($keyFile);
        $signature = self::crypto()->sign(self::DATA, $key, $algo);

        static::assertInstanceOf(RSASignature::class, $signature);
        static::assertSame(self::modulusLength($key), mb_strlen($signature->bitString()->string(), '8bit'));
        static::assertTrue(self::crypto()->verify(self::DATA, $signature, $key->publicKeyInfo(), $algo));
        static::assertFalse(self::crypto()->verify('PAYLOAD.', $signature, $key->publicKeyInfo(), $algo));
    }

    #[Test]
    public function signingIsRandomizedByTheSalt(): void
    {
        $key = self::privateKey('rsa-key.pem');
        $algo = RSASSAPSSAlgorithmIdentifier::create(SHA256AlgorithmIdentifier::create());

        static::assertNotSame(
            self::crypto()->sign(self::DATA, $key, $algo)->bitString()->string(),
            self::crypto()->sign(self::DATA, $key, $algo)->bitString()->string()
        );
    }

    #[Test]
    public function signingWithoutSaltIsDeterministic(): void
    {
        $key = self::privateKey('rsa-key.pem');
        $algo = RSASSAPSSAlgorithmIdentifier::create(SHA256AlgorithmIdentifier::create(), null, 0);

        static::assertSame(
            self::crypto()->sign(self::DATA, $key, $algo)->bitString()->string(),
            self::crypto()->sign(self::DATA, $key, $algo)->bitString()->string()
        );
    }

    #[Test]
    public function signingWithAKeyTooShortForTheSaltFails(): void
    {
        // emLen 128 < hLen 32 + sLen 95 + 2
        $algo = RSASSAPSSAlgorithmIdentifier::create(SHA256AlgorithmIdentifier::create(), null, 95);

        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessage('A 1025 bit RSA key is too short for RSASSA-PSS with sha256 and a 95 byte salt.');
        self::crypto()->sign(self::DATA, self::privateKey('rsa-1025-key.pem'), $algo);
    }

    #[Test]
    public function theLongestSaltAKeyAllowsCanBeUsed(): void
    {
        // emLen 128 = hLen 32 + sLen 94 + 2: the padding string is empty
        $key = self::privateKey('rsa-1025-key.pem');
        $algo = RSASSAPSSAlgorithmIdentifier::create(SHA256AlgorithmIdentifier::create(), null, 94);

        $signature = self::crypto()->sign(self::DATA, $key, $algo);

        static::assertTrue(self::crypto()->verify(self::DATA, $signature, $key->publicKeyInfo(), $algo));
    }

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
        yield 'leaf of a chain' => ['chain-leaf.pem', 'chain-root.pem'];
        yield 'reproducer' => ['reproducer-cert.pem', 'reproducer-cert.pem'];
    }

    #[Test]
    #[DataProvider('certificateProvider')]
    public function verifyOpenSSLSignature(string $certFile, string $issuerFile): void
    {
        $cert = self::certificate($certFile);
        $issuerKey = self::certificate($issuerFile)->tbsCertificate()->subjectPublicKeyInfo();
        $data = $cert->tbsCertificate()
            ->toASN1()
            ->toDER();
        $algo = $cert->signatureAlgorithm();

        static::assertTrue(self::crypto()->supportsSignatureAlgorithm($algo));
        static::assertTrue(self::crypto()->verify($data, $cert->signatureValue(), $issuerKey, $algo));
        static::assertFalse(self::crypto()->verify($data . "\0", $cert->signatureValue(), $issuerKey, $algo));
    }

    #[Test]
    public function tamperedSignatureDoesNotVerify(): void
    {
        [$data, $sig, $key, $algo] = self::fixture();
        $sig[100] = chr(ord($sig[100]) ^ 0x01);

        static::assertFalse(self::verify($data, $sig, $key, $algo));
    }

    /**
     * @return Iterator<string, array{int}>
     */
    public static function wrongSaltLengthProvider(): Iterator
    {
        yield 'shorter' => [31];
        yield 'longer' => [33];
        yield 'none' => [0];
        yield 'longer than the key allows' => [300];
    }

    #[Test]
    #[DataProvider('wrongSaltLengthProvider')]
    public function wrongSaltLengthDoesNotVerify(int $saltLength): void
    {
        [$data, $sig, $key] = self::fixture();
        $algo = RSASSAPSSAlgorithmIdentifier::create(SHA256AlgorithmIdentifier::create(), null, $saltLength);

        static::assertFalse(self::verify($data, $sig, $key, $algo));
    }

    #[Test]
    public function wrongHashDoesNotVerify(): void
    {
        [$data, $sig, $key] = self::fixture();
        $algo = RSASSAPSSAlgorithmIdentifier::create(
            SHA384AlgorithmIdentifier::create(),
            SHA256AlgorithmIdentifier::create(),
            32
        );

        static::assertFalse(self::verify($data, $sig, $key, $algo));
    }

    #[Test]
    public function wrongMaskGenerationHashDoesNotVerify(): void
    {
        [$data, $sig, $key] = self::fixture();
        $algo = RSASSAPSSAlgorithmIdentifier::create(
            SHA256AlgorithmIdentifier::create(),
            SHA1AlgorithmIdentifier::create(),
            32
        );

        static::assertFalse(self::verify($data, $sig, $key, $algo));
    }

    #[Test]
    public function truncatedSignatureDoesNotVerify(): void
    {
        [$data, $sig, $key, $algo] = self::fixture();

        static::assertFalse(self::verify($data, substr($sig, 0, -1), $key, $algo));
        static::assertFalse(self::verify($data, substr($sig, 1), $key, $algo));
    }

    #[Test]
    public function oversizedSignatureDoesNotVerify(): void
    {
        [$data, $sig, $key, $algo] = self::fixture();

        static::assertFalse(self::verify($data, "\0" . $sig, $key, $algo));
        static::assertFalse(self::verify($data, $sig . "\0", $key, $algo));
    }

    #[Test]
    public function signatureNotBelowTheModulusDoesNotVerify(): void
    {
        [$data, $sig, $key, $algo] = self::fixture();

        static::assertFalse(self::verify($data, str_repeat("\xff", mb_strlen($sig, '8bit')), $key, $algo));
        // the error OpenSSL queued is not left behind for the next caller
        static::assertFalse(openssl_error_string());
    }

    #[Test]
    public function emptySignatureDoesNotVerify(): void
    {
        [$data, , $key, $algo] = self::fixture();

        static::assertFalse(self::verify($data, '', $key, $algo));
    }

    #[Test]
    public function wellFormedEncodedMessageVerifies(): void
    {
        // makes sure the encoder below is right, so that a failure of the tests that alter it means what it says
        $key = self::privateKey('rsa-key.pem');

        static::assertTrue(self::verifyEncoded($key, self::encode($key, 32)));
        static::assertTrue(self::verifyEncoded($key, self::encode($key, 0), 0));
    }

    #[Test]
    public function wrongTrailerDoesNotVerify(): void
    {
        $key = self::privateKey('rsa-key.pem');
        $em = self::encode($key, 32);
        $em[mb_strlen($em, '8bit') - 1] = "\xbb";

        static::assertFalse(self::verifyEncoded($key, $em));
    }

    #[Test]
    public function nonZeroPaddingDoesNotVerify(): void
    {
        $key = self::privateKey('rsa-key.pem');

        static::assertFalse(self::verifyEncoded($key, self::encode($key, 32, "\x00\x01")));
        static::assertFalse(self::verifyEncoded($key, self::encode($key, 32, "\x01\x00")));
    }

    #[Test]
    public function wrongSeparatorDoesNotVerify(): void
    {
        $key = self::privateKey('rsa-key.pem');

        static::assertFalse(self::verifyEncoded($key, self::encode($key, 32, null, "\x02")));
        static::assertFalse(self::verifyEncoded($key, self::encode($key, 32, null, "\x00")));
    }

    #[Test]
    public function setBitLeftOfEmBitsDoesNotVerify(): void
    {
        // the leftmost bit of a 2048 bit key's encoded message is outside emBits: setting it must fail the
        // signature, though clearing it again while unmasking would otherwise yield a valid encoding
        $key = self::privateKey('rsa-key.pem');
        $n = self::modulus($key);
        for ($i = 0; ; ++$i) {
            $em = self::encode($key, 32, null, "\x01", (string) $i);
            $em[0] = chr(ord($em[0]) | 0x80);
            if (strcmp($em, $n) < 0) {
                break;
            }
        }

        static::assertFalse(self::verifyEncoded($key, $em));
    }

    #[Test]
    public function leadingByteOfAShortEncodedMessageMustBeZero(): void
    {
        // with a 1025 bit modulus the encoded message is a byte shorter than the signature, whose leading byte
        // must then be zero
        $key = self::privateKey('rsa-1025-key.pem');
        $n = self::modulus($key);
        for ($i = 0; ; ++$i) {
            $em = "\x01" . self::encode($key, 32, null, "\x01", (string) $i);
            if (strcmp($em, $n) < 0) {
                break;
            }
        }

        static::assertTrue(self::verifyEncoded($key, self::encode($key, 32, null, "\x01", (string) $i)));
        static::assertFalse(self::verifyEncoded($key, $em));
    }

    /**
     * @return Iterator<string, array{string}>
     */
    public static function unsupportedParametersProvider(): Iterator
    {
        $oid = '06092a864886f70d01010a';
        yield 'MD5' => ['303f' . $oid . '3032a00e300c06082a864886f70d02050500a11b301906092a864886f70d010108' .
            '300c06082a864886f70d02050500a203020110',
            'RSASSA-PSS hash algorithm md5 not supported.', ];
        yield 'unknown hash' => ['301e' . $oid . '3011a00f300d06092a864886f70d0101630500',
            'RSASSA-PSS hash algorithm 1.2.840.113549.1.1.99 not supported.', ];
        yield 'MGF1 over MD5' => ['302a' . $oid . '301da11b301906092a864886f70d010108300c06082a864886f70d02050500',
            'RSASSA-PSS MGF1 hash algorithm md5 not supported.', ];
        yield 'another mask generation function' => ['301e' . $oid . '3011a10f300d06092a864886f70d0101630500',
            'RSASSA-PSS mask generation function 1.2.840.113549.1.1.99 not supported.', ];
        yield 'trailer field 2' => ['3012' . $oid . '3005a303020102', 'RSASSA-PSS trailer field 2 not supported.'];
    }

    #[Test]
    #[DataProvider('unsupportedParametersProvider')]
    public function unsupportedParametersAreNotSupported(string $der, string $message): void
    {
        $algo = self::algorithm($der);

        static::assertFalse(self::crypto()->supportsSignatureAlgorithm($algo));
    }

    #[Test]
    #[DataProvider('unsupportedParametersProvider')]
    public function verifyRefusesUnsupportedParameters(string $der, string $message): void
    {
        [$data, $sig, $key] = self::fixture();

        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessage($message);
        self::verify($data, $sig, $key, self::algorithm($der));
    }

    #[Test]
    #[DataProvider('unsupportedParametersProvider')]
    public function signRefusesUnsupportedParameters(string $der, string $message): void
    {
        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessage($message);
        self::crypto()->sign(self::DATA, self::privateKey('rsa-key.pem'), self::algorithm($der));
    }

    #[Test]
    public function supportedParametersAreSupported(): void
    {
        static::assertTrue(self::crypto()->supportsSignatureAlgorithm(RSASSAPSSAlgorithmIdentifier::create()));
        static::assertTrue(
            self::crypto()->supportsSignatureAlgorithm(
                RSASSAPSSAlgorithmIdentifier::createWithoutParameters()
            )
        );
        static::assertTrue(
            self::crypto()->supportsSignatureAlgorithm(
                RSASSAPSSAlgorithmIdentifier::create(SHA512AlgorithmIdentifier::create())
            )
        );
        // the hash identifiers keep the NULL parameters OpenSSL gives them
        static::assertTrue(
            self::crypto()->supportsSignatureAlgorithm(self::certificate('sha384.pem')->signatureAlgorithm())
        );
    }

    #[Test]
    public function otherAlgorithmsAreStillSupported(): void
    {
        static::assertTrue(
            self::crypto()->supportsSignatureAlgorithm(SHA256WithRSAEncryptionAlgorithmIdentifier::create())
        );
    }

    #[Test]
    public function aKeyRestrictedToPSSCannotBeUsedForPKCS1(): void
    {
        $this->expectException(UnexpectedValueException::class);
        self::crypto()->sign(
            self::DATA,
            self::privateKey('pss-key.pem'),
            SHA256WithRSAEncryptionAlgorithmIdentifier::create()
        );
    }

    /**
     * @return Iterator<string, array{RSASSAPSSAlgorithmIdentifier, RSASSAPSSAlgorithmIdentifier, bool}>
     */
    public static function keyRestrictionProvider(): Iterator
    {
        $sha256 = SHA256AlgorithmIdentifier::create();
        $key = RSASSAPSSAlgorithmIdentifier::create($sha256, null, 32);
        yield 'the same parameters' => [$key, RSASSAPSSAlgorithmIdentifier::create($sha256, null, 32), true];
        yield 'a longer salt' => [$key, RSASSAPSSAlgorithmIdentifier::create($sha256, null, 64), true];
        yield 'a shorter salt' => [$key, RSASSAPSSAlgorithmIdentifier::create($sha256, null, 31), false];
        yield 'another hash' => [$key, RSASSAPSSAlgorithmIdentifier::create(SHA384AlgorithmIdentifier::create()), false];
        yield 'another MGF1 hash' => [
            $key,
            RSASSAPSSAlgorithmIdentifier::create($sha256, SHA1AlgorithmIdentifier::create(), 32),
            false,
        ];
        yield 'the default parameters' => [$key, RSASSAPSSAlgorithmIdentifier::create(), false];
        yield 'another trailer field' => [
            RSASSAPSSAlgorithmIdentifier::create($sha256, null, 32, 2),
            RSASSAPSSAlgorithmIdentifier::create($sha256, null, 32),
            false,
        ];
        // parameters with the default values are present all the same, and restrict the key to SHA-1
        yield 'a key with default parameters, SHA-1' => [
            RSASSAPSSAlgorithmIdentifier::create(),
            RSASSAPSSAlgorithmIdentifier::create(),
            true,
        ];
        yield 'a key with default parameters, SHA-256' => [
            RSASSAPSSAlgorithmIdentifier::create(),
            RSASSAPSSAlgorithmIdentifier::create($sha256),
            false,
        ];
        yield 'a key without parameters' => [
            RSASSAPSSAlgorithmIdentifier::createWithoutParameters(),
            RSASSAPSSAlgorithmIdentifier::create(SHA512AlgorithmIdentifier::create(), SHA1AlgorithmIdentifier::create(), 0),
            true,
        ];
    }

    #[Test]
    #[DataProvider('keyRestrictionProvider')]
    public function signingRespectsTheRestrictionsOfTheKey(
        RSASSAPSSAlgorithmIdentifier $keyAlgo,
        RSASSAPSSAlgorithmIdentifier $algo,
        bool $permitted
    ): void {
        $key = self::restrictedPrivateKey($keyAlgo);
        if (! $permitted) {
            $this->expectException(UnexpectedValueException::class);
            $this->expectExceptionMessage('RSASSA-PSS parameters are not permitted by the restrictions of the key.');
        }
        $signature = self::crypto()->sign(self::DATA, $key, $algo);

        static::assertTrue(self::crypto()->verify(self::DATA, $signature, self::restrictedPublicKey($keyAlgo), $algo));
    }

    #[Test]
    #[DataProvider('keyRestrictionProvider')]
    public function verificationRespectsTheRestrictionsOfTheKey(
        RSASSAPSSAlgorithmIdentifier $keyAlgo,
        RSASSAPSSAlgorithmIdentifier $algo,
        bool $permitted
    ): void {
        // the same key material without restrictions signs whatever it is asked to
        $unrestricted = self::privateKey('rsa-key.pem');
        $signature = self::crypto()->sign(self::DATA, $unrestricted, $algo);

        static::assertTrue(self::crypto()->verify(self::DATA, $signature, $unrestricted->publicKeyInfo(), $algo));
        static::assertSame(
            $permitted,
            self::crypto()->verify(self::DATA, $signature, self::restrictedPublicKey($keyAlgo), $algo)
        );
    }

    #[Test]
    public function aNonRSAKeyIsRefused(): void
    {
        $key = PrivateKeyInfo::fromPEM(PEM::fromFile(TEST_ASSETS_DIR . '/ec/private_key.pem'));

        $this->expectException(UnexpectedValueException::class);
        self::crypto()->sign(self::DATA, $key, RSASSAPSSAlgorithmIdentifier::create());
    }

    private static function crypto(): OpenSSLCrypto
    {
        return new OpenSSLCrypto();
    }

    private static function privateKey(string $file): PrivateKeyInfo
    {
        return PrivateKeyInfo::fromPEM(PEM::fromFile(TEST_ASSETS_DIR . '/rsassa-pss/' . $file));
    }

    private static function certificate(string $file): Certificate
    {
        return Certificate::fromPEM(PEM::fromFile(TEST_ASSETS_DIR . '/rsassa-pss/' . $file));
    }

    private static function algorithm(string $der): RSASSAPSSAlgorithmIdentifier
    {
        $algo = AlgorithmIdentifier::fromASN1(Sequence::fromDER((string) hex2bin($der)));
        static::assertInstanceOf(RSASSAPSSAlgorithmIdentifier::class, $algo);

        return $algo;
    }

    /**
     * The signed data, signature, signer's key and algorithm of a certificate OpenSSL signed with SHA-256 and a
     * 32 byte salt.
     *
     * @return array{string, string, PublicKeyInfo, RSASSAPSSAlgorithmIdentifier}
     */
    private static function fixture(): array
    {
        $cert = self::certificate('sha256-salt32.pem');
        $algo = $cert->signatureAlgorithm();
        static::assertInstanceOf(RSASSAPSSAlgorithmIdentifier::class, $algo);

        return [
            $cert->tbsCertificate()
                ->toASN1()
                ->toDER(),
            $cert->signatureValue()
                ->bitString()
                ->string(),
            $cert->tbsCertificate()
                ->subjectPublicKeyInfo(),
            $algo,
        ];
    }

    private static function verify(
        string $data,
        string $signature,
        PublicKeyInfo $key,
        RSASSAPSSAlgorithmIdentifier $algo
    ): bool {
        return self::crypto()->verify($data, RSASignature::fromSignatureString($signature), $key, $algo);
    }

    /**
     * @return array{bits: int, rsa: array{n: string}}
     */
    private static function details(PrivateKeyInfo $key): array
    {
        $pkey = openssl_pkey_get_private((string) $key->toPEM());
        static::assertNotFalse($pkey);
        $details = openssl_pkey_get_details($pkey);
        static::assertIsArray($details);

        /** @var array{bits: int, rsa: array{n: string}} $details */
        return $details;
    }

    private static function modulusLength(PrivateKeyInfo $key): int
    {
        return intdiv(self::details($key)['bits'] + 7, 8);
    }

    /**
     * The modulus as a big endian string of the length of a signature.
     */
    private static function modulus(PrivateKeyInfo $key): string
    {
        return str_pad(self::details($key)['rsa']['n'], self::modulusLength($key), "\0", STR_PAD_LEFT);
    }

    /**
     * The RSA key of rsa-key.pem, restricted to RSASSA-PSS with the given parameters.
     */
    private static function restrictedPrivateKey(RSASSAPSSAlgorithmIdentifier $keyAlgo): PrivateKeyInfo
    {
        return PrivateKeyInfo::create($keyAlgo, self::privateKey('rsa-key.pem')->privateKeyData());
    }

    private static function restrictedPublicKey(RSASSAPSSAlgorithmIdentifier $keyAlgo): PublicKeyInfo
    {
        return PublicKeyInfo::create($keyAlgo, self::privateKey('rsa-key.pem')->publicKeyInfo()->publicKeyData());
    }

    /**
     * EMSA-PSS-ENCODE of DATA with SHA-256 and MGF1 over SHA-256, with a deterministic salt.
     *
     * @param null|string $ps Padding string replacing the leading bytes of the zero one
     * @param string $separator Byte between the padding string and the salt
     */
    private static function encode(
        PrivateKeyInfo $key,
        int $saltLength,
        ?string $ps = null,
        string $separator = "\x01",
        string $seed = ''
    ): string {
        $emBits = self::details($key)['bits'] - 1;
        $emLen = intdiv($emBits + 7, 8);
        $salt = mb_substr(hash('sha512', $seed, true), 0, $saltLength, '8bit');
        $h = hash('sha256', str_repeat("\0", 8) . hash('sha256', self::DATA, true) . $salt, true);
        $psLen = $emLen - $saltLength - 32 - 2;
        $padding = str_repeat("\0", $psLen);
        if ($ps !== null) {
            $padding = $ps . mb_substr($padding, mb_strlen($ps, '8bit'), null, '8bit');
        }
        $db = $padding . $separator . $salt;
        $mask = '';
        for ($counter = 0; mb_strlen($mask, '8bit') < $emLen - 33; ++$counter) {
            $mask .= hash('sha256', $h . pack('N', $counter), true);
        }
        $maskedDB = $db ^ mb_substr($mask, 0, $emLen - 33, '8bit');
        $maskedDB[0] = chr(ord($maskedDB[0]) & (0xFF >> (8 * $emLen - $emBits)));

        return $maskedDB . $h . "\xbc";
    }

    /**
     * Put an encoded message through the raw RSA private key operation, and verify the signature this gives.
     */
    private static function verifyEncoded(
        PrivateKeyInfo $key,
        string $em,
        int $saltLength = 32
    ): bool {
        $k = self::modulusLength($key);
        static::assertTrue(
            openssl_private_encrypt(
                str_pad($em, $k, "\0", STR_PAD_LEFT),
                $signature,
                (string) $key->toPEM(),
                OPENSSL_NO_PADDING
            )
        );
        static::assertIsString($signature);

        return self::crypto()->verify(
            self::DATA,
            Signature::fromSignatureData($signature, RSASSAPSSAlgorithmIdentifier::create()),
            $key->publicKeyInfo(),
            RSASSAPSSAlgorithmIdentifier::create(SHA256AlgorithmIdentifier::create(), null, $saltLength)
        );
    }
}
