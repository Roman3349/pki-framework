<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\Test\CryptoTypes\Unit\AlgoId\Signature;

use Iterator;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Exception\DecodeException;
use SpomkyLabs\Pki\ASN1\Type\Constructed\Sequence;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\AlgorithmIdentifier;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Asymmetric\ECPublicKeyAlgorithmIdentifier;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Asymmetric\RSAEncryptionAlgorithmIdentifier;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Asymmetric\RSAPSSSSAEncryptionAlgorithmIdentifier;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Feature\AsymmetricCryptoAlgorithmIdentifier;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Feature\HashAlgorithmIdentifier;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Feature\SignatureAlgorithmIdentifier;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\GenericAlgorithmIdentifier;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Hash\HMACWithSHA256AlgorithmIdentifier;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Hash\MD5AlgorithmIdentifier;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Hash\SHA1AlgorithmIdentifier;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Hash\SHA224AlgorithmIdentifier;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Hash\SHA256AlgorithmIdentifier;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Hash\SHA384AlgorithmIdentifier;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Hash\SHA512AlgorithmIdentifier;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Signature\RSASSAPSSAlgorithmIdentifier;
use SpomkyLabs\Pki\CryptoTypes\Signature\RSASignature;
use SpomkyLabs\Pki\CryptoTypes\Signature\Signature;
use UnexpectedValueException;

/**
 * @internal
 */
final class RSASSAPSSAITest extends TestCase
{
    private const OID = '06092a864886f70d01010a';

    private const SHA256 = '300b0609608648016503040201';

    private const MGF1_SHA256 = '301806092a864886f70d010108' . self::SHA256;

    /**
     * @return Iterator<string, array{RSASSAPSSAlgorithmIdentifier, string}>
     */
    public static function encodingProvider(): Iterator
    {
        yield 'defaults are an empty sequence' => [RSASSAPSSAlgorithmIdentifier::create(), '300d' . self::OID . '3000'];
        yield 'explicit defaults are omitted' => [
            RSASSAPSSAlgorithmIdentifier::create(SHA1AlgorithmIdentifier::create(), SHA1AlgorithmIdentifier::create(), 20, 1),
            '300d' . self::OID . '3000',
        ];
        yield 'absent parameters' => [RSASSAPSSAlgorithmIdentifier::createWithoutParameters(), '300b' . self::OID];
        yield 'SHA-256 sets MGF1 and salt length' => [
            RSASSAPSSAlgorithmIdentifier::create(SHA256AlgorithmIdentifier::create()),
            '303d' . self::OID . '3030a00d' . self::SHA256 . 'a11a' . self::MGF1_SHA256 . 'a203020120',
        ];
        yield 'hash only' => [
            RSASSAPSSAlgorithmIdentifier::create(SHA256AlgorithmIdentifier::create(), SHA1AlgorithmIdentifier::create(), 20),
            '301c' . self::OID . '300fa00d' . self::SHA256,
        ];
        yield 'MGF1 hash only' => [
            RSASSAPSSAlgorithmIdentifier::create(null, SHA256AlgorithmIdentifier::create()),
            '3029' . self::OID . '301ca11a' . self::MGF1_SHA256,
        ];
        yield 'salt length only' => [
            RSASSAPSSAlgorithmIdentifier::create(null, null, 0),
            '3012' . self::OID . '3005a203020100',
        ];
        yield 'trailer field only' => [
            RSASSAPSSAlgorithmIdentifier::create(null, null, null, 2),
            '3012' . self::OID . '3005a303020102',
        ];
        yield 'MD5 salt length defaults to 16' => [
            RSASSAPSSAlgorithmIdentifier::create(MD5AlgorithmIdentifier::create()),
            '303f' . self::OID . '3032a00e300c06082a864886f70d02050500a11b301906092a864886f70d010108' .
            '300c06082a864886f70d02050500a203020110',
        ];
    }

    #[Test]
    #[DataProvider('encodingProvider')]
    public function encode(RSASSAPSSAlgorithmIdentifier $algo, string $der): void
    {
        static::assertSame($der, bin2hex($algo->toASN1()->toDER()));
    }

    #[Test]
    #[DataProvider('encodingProvider')]
    public function decodeRoundTrips(RSASSAPSSAlgorithmIdentifier $algo, string $der): void
    {
        $decoded = AlgorithmIdentifier::fromASN1(Sequence::fromDER((string) hex2bin($der)));

        static::assertInstanceOf(RSASSAPSSAlgorithmIdentifier::class, $decoded);
        static::assertSame($der, bin2hex($decoded->toASN1()->toDER()));
        static::assertSame($algo->hashAlgorithm()->oid(), $decoded->hashAlgorithm()->oid());
        static::assertSame($algo->maskGenAlgorithm()->oid(), $decoded->maskGenAlgorithm()->oid());
        static::assertSame($algo->maskGenHashAlgorithm()?->oid(), $decoded->maskGenHashAlgorithm()?->oid());
        static::assertSame($algo->saltLength(), $decoded->saltLength());
        static::assertSame($algo->trailerField(), $decoded->trailerField());
        static::assertSame($algo->hasParameters(), $decoded->hasParameters());
    }

    /**
     * @return Iterator<string, array{null|HashAlgorithmIdentifier, int}>
     */
    public static function saltLengthProvider(): Iterator
    {
        yield 'SHA-1' => [null, 20];
        yield 'SHA-224' => [SHA224AlgorithmIdentifier::create(), 28];
        yield 'SHA-256' => [SHA256AlgorithmIdentifier::create(), 32];
        yield 'SHA-384' => [SHA384AlgorithmIdentifier::create(), 48];
        yield 'SHA-512' => [SHA512AlgorithmIdentifier::create(), 64];
    }

    #[Test]
    #[DataProvider('saltLengthProvider')]
    public function saltLengthDefaultsToTheHashLength(
        ?HashAlgorithmIdentifier $hash,
        int $length
    ): void {
        $algo = RSASSAPSSAlgorithmIdentifier::create($hash);

        static::assertSame($length, $algo->saltLength());
        static::assertSame($algo->hashAlgorithm()->oid(), $algo->maskGenHashAlgorithm()?->oid());
        static::assertSame(AlgorithmIdentifier::OID_MGF1, $algo->maskGenAlgorithm()->oid());
        static::assertSame(1, $algo->trailerField());
        static::assertTrue($algo->hasParameters());
    }

    #[Test]
    public function saltLengthMustBeGivenForAnUnknownHash(): void
    {
        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessage('Salt length must be given for hash algorithm hmacWithSHA256.');
        RSASSAPSSAlgorithmIdentifier::create(HMACWithSHA256AlgorithmIdentifier::create());
    }

    #[Test]
    public function aGivenSaltLengthIsAcceptedForAnUnknownHash(): void
    {
        static::assertSame(
            7,
            RSASSAPSSAlgorithmIdentifier::create(HMACWithSHA256AlgorithmIdentifier::create(), null, 7)->saltLength()
        );
    }

    #[Test]
    public function negativeSaltLengthIsRefused(): void
    {
        $this->expectException(UnexpectedValueException::class);
        RSASSAPSSAlgorithmIdentifier::create(null, null, -1);
    }

    #[Test]
    public function absentParametersReadAsTheDefaults(): void
    {
        $algo = AlgorithmIdentifier::fromASN1(Sequence::fromDER((string) hex2bin('300b' . self::OID)));

        static::assertInstanceOf(RSASSAPSSAlgorithmIdentifier::class, $algo);
        static::assertFalse($algo->hasParameters());
        static::assertSame(AlgorithmIdentifier::OID_SHA1, $algo->hashAlgorithm()->oid());
        static::assertSame(AlgorithmIdentifier::OID_MGF1, $algo->maskGenAlgorithm()->oid());
        static::assertSame(AlgorithmIdentifier::OID_SHA1, $algo->maskGenHashAlgorithm()?->oid());
        static::assertSame(20, $algo->saltLength());
        static::assertSame(1, $algo->trailerField());
    }

    #[Test]
    public function nullParametersAreKept(): void
    {
        // earlier versions of this library encoded the key algorithm with NULL parameters
        $der = (string) hex2bin('300d' . self::OID . '0500');
        $algo = AlgorithmIdentifier::fromASN1(Sequence::fromDER($der));

        static::assertInstanceOf(RSASSAPSSAlgorithmIdentifier::class, $algo);
        static::assertFalse($algo->hasParameters());
        static::assertSame(20, $algo->saltLength());
        static::assertSame($der, $algo->toASN1()->toDER());
        static::assertSame($der, RSAPSSSSAEncryptionAlgorithmIdentifier::create()->toASN1()->toDER());
    }

    #[Test]
    public function explicitlyEncodedDefaultsAreKept(): void
    {
        // not DER, but the parameters are signed: re-encoding them must not change them
        $der = (string) hex2bin(
            '303e06092a864886f70d01010a3031a00b300906052b0e03021a0500a118301606092a864886f70d010108' .
            '300906052b0e03021a0500a203020114a303020101'
        );
        $algo = AlgorithmIdentifier::fromASN1(Sequence::fromDER($der));

        static::assertInstanceOf(RSASSAPSSAlgorithmIdentifier::class, $algo);
        static::assertSame($der, $algo->toASN1()->toDER());
        static::assertSame(AlgorithmIdentifier::OID_SHA1, $algo->hashAlgorithm()->oid());
        static::assertSame(AlgorithmIdentifier::OID_SHA1, $algo->maskGenHashAlgorithm()?->oid());
        static::assertSame(20, $algo->saltLength());
        static::assertSame(1, $algo->trailerField());
        static::assertTrue($algo->hasParameters());
    }

    #[Test]
    public function decodeOpenSSLParameters(): void
    {
        // as `openssl req -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:48 -sha384` encodes them, with
        // NULL hash parameters
        $der = (string) hex2bin(
            '304106092a864886f70d01010a3034a00f300d06096086480165030402020500a11c301a06092a864886f70d010108' .
            '300d06096086480165030402020500a203020130'
        );
        $algo = AlgorithmIdentifier::fromASN1(Sequence::fromDER($der));

        static::assertInstanceOf(RSASSAPSSAlgorithmIdentifier::class, $algo);
        static::assertSame(AlgorithmIdentifier::OID_SHA384, $algo->hashAlgorithm()->oid());
        static::assertSame(AlgorithmIdentifier::OID_SHA384, $algo->maskGenHashAlgorithm()?->oid());
        static::assertSame(48, $algo->saltLength());
        static::assertSame(1, $algo->trailerField());
        static::assertSame($der, $algo->toASN1()->toDER());
    }

    #[Test]
    public function anotherMaskGenerationFunctionIsKept(): void
    {
        $der = (string) hex2bin('301e06092a864886f70d01010a3011a10f300d06092a864886f70d0101630500');
        $algo = AlgorithmIdentifier::fromASN1(Sequence::fromDER($der));

        static::assertInstanceOf(RSASSAPSSAlgorithmIdentifier::class, $algo);
        static::assertSame('1.2.840.113549.1.1.99', $algo->maskGenAlgorithm()->oid());
        static::assertInstanceOf(GenericAlgorithmIdentifier::class, $algo->maskGenAlgorithm());
        static::assertNull($algo->maskGenHashAlgorithm());
        static::assertSame($der, $algo->toASN1()->toDER());
    }

    /**
     * @return Iterator<string, array{string}>
     */
    public static function invalidParametersProvider(): Iterator
    {
        yield 'MGF1 without hash' => ['301c06092a864886f70d01010a300fa10d300b06092a864886f70d010108'];
        yield 'negative salt length' => ['301206092a864886f70d01010a3005a2030201ff'];
        yield 'unknown element' => ['301206092a864886f70d01010a3005a403020101'];
        yield 'untagged element' => ['301006092a864886f70d01010a3003020101'];
        yield 'parameters neither NULL nor sequence' => ['300e06092a864886f70d01010a020101'];
    }

    #[Test]
    #[DataProvider('invalidParametersProvider')]
    public function invalidParametersAreRefused(string $der): void
    {
        $this->expectException(UnexpectedValueException::class);
        AlgorithmIdentifier::fromASN1(Sequence::fromDER((string) hex2bin($der)));
    }

    #[Test]
    public function duplicateParametersAreRefused(): void
    {
        $this->expectException(DecodeException::class);
        AlgorithmIdentifier::fromASN1(
            Sequence::fromDER((string) hex2bin('301706092a864886f70d01010a300aa203020120a203020130'))
        );
    }

    #[Test]
    public function saltLengthTooLargeIsRefused(): void
    {
        $this->expectException(DecodeException::class);
        AlgorithmIdentifier::fromASN1(
            Sequence::fromDER((string) hex2bin('301b06092a864886f70d01010a300ea20c020a01000000000000000000'))
        );
    }

    #[Test]
    public function identifierIsBothASignatureAndAKeyAlgorithm(): void
    {
        $algo = RSASSAPSSAlgorithmIdentifier::create();

        static::assertInstanceOf(SignatureAlgorithmIdentifier::class, $algo);
        static::assertInstanceOf(AsymmetricCryptoAlgorithmIdentifier::class, $algo);
        static::assertSame(AlgorithmIdentifier::OID_RSASSA_PSS_ENCRYPTION, $algo->oid());
        static::assertSame('rsassa-pss', $algo->name());
    }

    #[Test]
    public function supportsRSAKeys(): void
    {
        $algo = RSASSAPSSAlgorithmIdentifier::create();

        static::assertTrue($algo->supportsKeyAlgorithm(RSAEncryptionAlgorithmIdentifier::create()));
        static::assertTrue($algo->supportsKeyAlgorithm(RSASSAPSSAlgorithmIdentifier::createWithoutParameters()));
        static::assertTrue($algo->supportsKeyAlgorithm(RSAPSSSSAEncryptionAlgorithmIdentifier::create()));
        static::assertFalse(
            $algo->supportsKeyAlgorithm(
                ECPublicKeyAlgorithmIdentifier::create(ECPublicKeyAlgorithmIdentifier::CURVE_PRIME256V1)
            )
        );
    }

    #[Test]
    public function signatureValueIsAnRSASignature(): void
    {
        static::assertInstanceOf(
            RSASignature::class,
            Signature::fromSignatureData('signature', RSASSAPSSAlgorithmIdentifier::create())
        );
    }
}
