<?php

declare(strict_types=1);

namespace SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Signature;

use function array_key_exists;
use SpomkyLabs\Pki\ASN1\Element;
use SpomkyLabs\Pki\ASN1\Type\Constructed\Sequence;
use SpomkyLabs\Pki\ASN1\Type\Primitive\Integer;
use SpomkyLabs\Pki\ASN1\Type\Primitive\NullType;
use SpomkyLabs\Pki\ASN1\Type\Tagged\ExplicitlyTaggedType;
use SpomkyLabs\Pki\ASN1\Type\UnspecifiedType;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\AlgorithmIdentifier;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Feature\AlgorithmIdentifierType;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Feature\AsymmetricCryptoAlgorithmIdentifier;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Feature\HashAlgorithmIdentifier;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\GenericAlgorithmIdentifier;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Hash\SHA1AlgorithmIdentifier;
use function sprintf;
use UnexpectedValueException;

/*
 * From RFC 4055 - 3.1.  RSASSA-PSS Public Keys
 * When RSASSA-PSS is used in an AlgorithmIdentifier, the parameters MUST
 * employ the RSASSA-PSS-params syntax.  The parameters may be either
 * absent or present when used as subject public key information.  The
 * parameters MUST be present when used in the algorithm identifier
 * associated with a signature value.
 *
 * RSASSA-PSS-params  ::=  SEQUENCE  {
 *     hashAlgorithm      [0] HashAlgorithm DEFAULT sha1Identifier,
 *     maskGenAlgorithm   [1] MaskGenAlgorithm DEFAULT mgf1SHA1Identifier,
 *     saltLength         [2] INTEGER DEFAULT 20,
 *     trailerField       [3] INTEGER DEFAULT 1  }
 */

/**
 * RSASSA-PSS signature algorithm identifier.
 *
 * The same object identifier names the signature algorithm and, in a SubjectPublicKeyInfo or a PrivateKeyInfo, an
 * RSA key restricted to it, so this identifier is also an asymmetric key algorithm identifier.
 *
 * When decoded, the parameters are kept as they were received so that re-encoding a signed structure does not
 * change it. Absent parameters, and the NULL parameters that earlier versions of this library produced, read as
 * the default values.
 *
 * @see https://tools.ietf.org/html/rfc4055#section-3.1
 * @see https://tools.ietf.org/html/rfc8017#appendix-A.2.3
 */
final class RSASSAPSSAlgorithmIdentifier extends RSASignatureAlgorithmIdentifier implements AsymmetricCryptoAlgorithmIdentifier
{
    /**
     * Default salt length.
     *
     * @var int
     */
    public const DEFAULT_SALT_LENGTH = 20;

    /**
     * Default trailer field, the only one RFC 8017 defines: the trailer byte 0xbc.
     *
     * @var int
     */
    public const DEFAULT_TRAILER_FIELD = 1;

    /**
     * Output length, in bytes, of the hash functions, used as the default salt length.
     *
     * @internal
     *
     * @var array<string, int>
     */
    private const MAP_HASH_OID_TO_LENGTH = [
        AlgorithmIdentifier::OID_MD5 => 16,
        AlgorithmIdentifier::OID_SHA1 => 20,
        AlgorithmIdentifier::OID_SHA224 => 28,
        AlgorithmIdentifier::OID_SHA256 => 32,
        AlgorithmIdentifier::OID_SHA384 => 48,
        AlgorithmIdentifier::OID_SHA512 => 64,
    ];

    /**
     * @param AlgorithmIdentifierType $hashAlgorithm Hash function applied to the message
     * @param AlgorithmIdentifierType $maskGenAlgorithm Mask generation function
     * @param null|AlgorithmIdentifierType $maskGenHashAlgorithm Hash function of MGF1, null for another function
     * @param null|NullType|Sequence $params Encoded parameters, null when absent
     */
    private function __construct(
        private readonly AlgorithmIdentifierType $hashAlgorithm,
        private readonly AlgorithmIdentifierType $maskGenAlgorithm,
        private readonly ?AlgorithmIdentifierType $maskGenHashAlgorithm,
        private readonly int $saltLength,
        private readonly int $trailerField,
        private readonly null|NullType|Sequence $params
    ) {
        parent::__construct(self::OID_RSASSA_PSS_ENCRYPTION);
    }

    /**
     * Create an identifier with RSASSA-PSS-params.
     *
     * The mask generation function is MGF1. When not given, its hash function is the one applied to the message,
     * and the salt is as long as the output of that function, as RFC 4055 section 3.1 recommends. Without any
     * argument, the parameters have the default values and are encoded as an empty sequence.
     *
     * @param null|HashAlgorithmIdentifier $hashAlgorithm Hash function, SHA-1 by default
     * @param null|HashAlgorithmIdentifier $maskGenHashAlgorithm Hash function of MGF1
     * @param null|int $saltLength Salt length in bytes
     */
    public static function create(
        ?HashAlgorithmIdentifier $hashAlgorithm = null,
        ?HashAlgorithmIdentifier $maskGenHashAlgorithm = null,
        ?int $saltLength = null,
        int $trailerField = self::DEFAULT_TRAILER_FIELD
    ): self {
        $hashAlgorithm ??= SHA1AlgorithmIdentifier::create();
        $maskGenHashAlgorithm ??= $hashAlgorithm;
        if ($saltLength === null) {
            if (! array_key_exists($hashAlgorithm->oid(), self::MAP_HASH_OID_TO_LENGTH)) {
                throw new UnexpectedValueException(sprintf(
                    'Salt length must be given for hash algorithm %s.',
                    $hashAlgorithm->name()
                ));
            }
            $saltLength = self::MAP_HASH_OID_TO_LENGTH[$hashAlgorithm->oid()];
        }
        if ($saltLength < 0) {
            throw new UnexpectedValueException('Salt length must not be negative.');
        }
        $maskGenAlgorithm = GenericAlgorithmIdentifier::create(
            self::OID_MGF1,
            UnspecifiedType::create($maskGenHashAlgorithm->toASN1())
        );
        // DER omits the fields that hold their default value
        $elements = [];
        if ($hashAlgorithm->oid() !== self::OID_SHA1) {
            $elements[] = ExplicitlyTaggedType::create(0, $hashAlgorithm->toASN1());
        }
        if ($maskGenHashAlgorithm->oid() !== self::OID_SHA1) {
            $elements[] = ExplicitlyTaggedType::create(1, $maskGenAlgorithm->toASN1());
        }
        if ($saltLength !== self::DEFAULT_SALT_LENGTH) {
            $elements[] = ExplicitlyTaggedType::create(2, Integer::create($saltLength));
        }
        if ($trailerField !== self::DEFAULT_TRAILER_FIELD) {
            $elements[] = ExplicitlyTaggedType::create(3, Integer::create($trailerField));
        }
        return new self(
            $hashAlgorithm,
            $maskGenAlgorithm,
            $maskGenHashAlgorithm,
            $saltLength,
            $trailerField,
            Sequence::create(...$elements)
        );
    }

    /**
     * Create an identifier without parameters.
     *
     * RFC 4055 allows the parameters to be absent in a SubjectPublicKeyInfo, for a key that may be used with any
     * RSASSA-PSS parameters. They must be present in the identifier of a signature.
     */
    public static function createWithoutParameters(): self
    {
        $default = self::create();

        return new self(
            $default->hashAlgorithm,
            $default->maskGenAlgorithm,
            $default->maskGenHashAlgorithm,
            $default->saltLength,
            $default->trailerField,
            null
        );
    }

    public static function fromASN1Params(?UnspecifiedType $params = null): self
    {
        $default = self::create();
        // absent parameters, or the NULL that earlier versions of this library produced, read as the defaults
        if ($params === null || $params->isType(Element::TYPE_NULL)) {
            return new self(
                $default->hashAlgorithm,
                $default->maskGenAlgorithm,
                $default->maskGenHashAlgorithm,
                $default->saltLength,
                $default->trailerField,
                $params?->asNull()
            );
        }
        $seq = $params->asSequence();
        $seq->assertUniqueTaggedElements('RSASSA-PSS-params');
        $count = 0;
        $hashAlgorithm = $default->hashAlgorithm;
        if ($seq->hasTagged(0)) {
            ++$count;
            $hashAlgorithm = AlgorithmIdentifier::fromASN1($seq->getTagged(0)->asExplicit()->asSequence());
        }
        $maskGenAlgorithm = $default->maskGenAlgorithm;
        $maskGenHashAlgorithm = $default->maskGenHashAlgorithm;
        if ($seq->hasTagged(1)) {
            ++$count;
            $mgf = $seq->getTagged(1)
                ->asExplicit()
                ->asSequence();
            $mgfOid = $mgf->at(0)
                ->asObjectIdentifier()
                ->oid();
            $mgfParams = $mgf->has(1) ? $mgf->at(1) : null;
            $maskGenAlgorithm = GenericAlgorithmIdentifier::create($mgfOid, $mgfParams);
            // the parameter of MGF1 is the hash function it is built on; another function is kept as it is, and
            // refused when it comes to signing or verifying
            $maskGenHashAlgorithm = null;
            if ($mgfOid === self::OID_MGF1) {
                if ($mgfParams === null) {
                    throw new UnexpectedValueException('MGF1 hash algorithm is missing.');
                }
                $maskGenHashAlgorithm = AlgorithmIdentifier::fromASN1($mgfParams->asSequence());
            }
        }
        $saltLength = self::DEFAULT_SALT_LENGTH;
        if ($seq->hasTagged(2)) {
            ++$count;
            $saltLength = $seq->getTagged(2)
                ->asExplicit()
                ->asInteger()
                ->intNumber();
            if ($saltLength < 0) {
                throw new UnexpectedValueException('Salt length must not be negative.');
            }
        }
        $trailerField = self::DEFAULT_TRAILER_FIELD;
        if ($seq->hasTagged(3)) {
            ++$count;
            $trailerField = $seq->getTagged(3)
                ->asExplicit()
                ->asInteger()
                ->intNumber();
        }
        if ($count !== $seq->count()) {
            throw new UnexpectedValueException('RSASSA-PSS-params has unexpected elements.');
        }
        // store the parameters as received so that re-encoding does not change them
        return new self(
            $hashAlgorithm,
            $maskGenAlgorithm,
            $maskGenHashAlgorithm,
            $saltLength,
            $trailerField,
            $seq
        );
    }

    public function name(): string
    {
        return 'rsassa-pss';
    }

    /**
     * Whether the identifier carries RSASSA-PSS-params, rather than absent or NULL parameters.
     */
    public function hasParameters(): bool
    {
        return $this->params instanceof Sequence;
    }

    /**
     * Get the hash function applied to the message.
     */
    public function hashAlgorithm(): AlgorithmIdentifierType
    {
        return $this->hashAlgorithm;
    }

    /**
     * Get the mask generation function.
     */
    public function maskGenAlgorithm(): AlgorithmIdentifierType
    {
        return $this->maskGenAlgorithm;
    }

    /**
     * Get the hash function MGF1 is built on, or null if the mask generation function is not MGF1.
     */
    public function maskGenHashAlgorithm(): ?AlgorithmIdentifierType
    {
        return $this->maskGenHashAlgorithm;
    }

    /**
     * Get the salt length in bytes.
     */
    public function saltLength(): int
    {
        return $this->saltLength;
    }

    /**
     * Get the trailer field.
     */
    public function trailerField(): int
    {
        return $this->trailerField;
    }

    /**
     * RSASSA-PSS accepts an RSA key, whether or not the key is restricted to RSASSA-PSS.
     */
    public function supportsKeyAlgorithm(AlgorithmIdentifier $algo): bool
    {
        return $algo->oid() === self::OID_RSA_ENCRYPTION || $algo->oid() === self::OID_RSASSA_PSS_ENCRYPTION;
    }

    /**
     * @return null|NullType|Sequence
     */
    protected function paramsASN1(): ?Element
    {
        return $this->params;
    }
}
