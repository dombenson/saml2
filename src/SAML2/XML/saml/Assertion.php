<?php

declare(strict_types=1);

namespace SAML2\XML\saml;

use DOMElement;
use DOMNode;
use DOMNodeList;
use Exception;
use RobRichards\XMLSecLibs\XMLSecEnc;
use RobRichards\XMLSecLibs\XMLSecurityKey;
use SAML2\Constants;
use SAML2\DOMDocumentFactory;
use SAML2\Exception\RuntimeException;
use SAML2\Utilities\Temporal;
use SAML2\Utils;
use SAML2\XML\Chunk;
use SAML2\XML\IdentifierTrait;
use SAML2\XML\SignedElementInterface;
use SAML2\XML\SignedElementTrait;
use Webmozart\Assert\Assert;

/**
 * Class representing a SAML 2 assertion.
 *
 * @package SimpleSAMLphp
 */
class Assertion implements SignedElementInterface
{
    use IdentifierTrait;
    use SignedElementTrait;

    /**
     * The identifier of this assertion.
     *
     * @var string
     */
    protected $id;

    /**
     * The issue timestamp of this assertion, as an UNIX timestamp.
     *
     * @var int
     */
    protected $issueInstant;

    /**
     * The issuer of this assertion.
     *
     * If the issuer's format is \SAML2\Constants::NAMEID_ENTITY, this property will just take the issuer's string
     * value.
     *
     * @var \SAML2\XML\saml\Issuer
     */
    protected $issuer;

    /**
     * The subject of this assertion
     *
     * @var \SAML2\XML\saml\Subject|null
     */
    protected $subject;

    /**
     * The encrypted Attributes.
     *
     * If this is not an empty array, these Attributes need decryption before they can be used.
     *
     * @var \DOMElement[]
     */
    protected $encryptedAttributes;

    /**
     * Private key we should use to encrypt the attributes.
     *
     * @var XMLSecurityKey|null
     */
    protected $encryptionKey;

    /**
     * The session expiration timestamp.
     *
     * @var int|null
     */
    protected $sessionNotOnOrAfter = null;

    /**
     * The session index for this user on the IdP.
     *
     * Contains null if no session index is present.
     *
     * @var string|null
     */
    protected $sessionIndex = null;

    /**
     * The timestamp the user was authenticated, as an UNIX timestamp.
     *
     * @var int|null
     */
    protected $authnInstant = null;

    /**
     * The authentication statement for this assertion.
     *
     * @var \SAML2\XML\saml\AuthnStatement[]
     */
    protected $authnStatement = [];

    /**
     * The authentication context reference for this assertion.
     *
     * @var string|null
     */
    protected $authnContextClassRef = null;

    /**
     * Authentication context declaration provided by value.
     *
     * See:
     * @url http://docs.oasis-open.org/security/saml/v2.0/saml-authn-context-2.0-os.pdf
     *
     * @var \SAML2\XML\Chunk|null
     */
    protected $authnContextDecl = null;

    /**
     * URI reference that identifies an authentication context declaration.
     *
     * The URI reference MAY directly resolve into an XML document containing the referenced declaration.
     *
     * @var string|null
     */
    protected $authnContextDeclRef = null;

    /**
     * The list of AuthenticatingAuthorities for this assertion.
     *
     * @var string[]
     */
    protected $AuthenticatingAuthority = [];

    /**
     * The attributes, as an associative array, indexed by attribute name
     *
     * To ease handling, all attribute values are represented as an array of values, also for values with a multiplicity
     * of single. There are 5 possible variants of datatypes for the values: a string, an integer, an array, a
     * DOMNodeList or a SAML2\XML\saml\NameID object.
     *
     * If the attribute is an eduPersonTargetedID, the values will be SAML2\XML\saml\NameID objects.
     * If the attribute value has an type-definition (xsi:string or xsi:int), the values will be of that type.
     * If the attribute value contains a nested XML structure, the values will be a DOMNodeList
     * In all other cases the values are treated as strings
     *
     * **WARNING** a DOMNodeList cannot be serialized without data-loss and should be handled explicitly
     *
     * @var array multi-dimensional array of \DOMNodeList|\SAML2\XML\saml\NameID|string|int|array
     */
    protected $attributes = [];

    /**
     * The attributes values types as per http://www.w3.org/2001/XMLSchema definitions
     * the variable is as an associative array, indexed by attribute name
     *
     * when parsing assertion, the variable will be:
     * - <attribute name> => [<Value1's xs type>|null, <xs type Value2>|null, ...]
     * array will always have the same size of the array of vaules in $attributes for the same <attribute name>
     *
     * when generating assertion, the varuable can be:
     * - null : backward compatibility
     * - <attribute name> => <xs type> : all values for the given attribute will have the same xs type
     * - <attribute name> => [<Value1's xs type>|null, <xs type Value2>|null, ...] : Nth value will have type of the
     *   Nth in the array
     *
     * @var array multi-dimensional array of array
     */
    protected $attributesValueTypes = [];

    /**
     * The NameFormat used on all attributes.
     *
     * If more than one NameFormat is used, this will contain the unspecified nameformat.
     *
     * @var string
     */
    protected $nameFormat = Constants::NAMEFORMAT_UNSPECIFIED;

    /**
     * The data needed to verify the signature.
     *
     * @var array|null
     */
    protected $signatureData = null;

    /**
     * Boolean that indicates if attributes are encrypted in the assertion or not.
     *
     * @var boolean
     */
    protected $requiredEncAttributes = false;

    /**
     * The SubjectConfirmation elements of the Subject in the assertion.
     *
     * @var \SAML2\XML\saml\SubjectConfirmation[]
     */
    protected $SubjectConfirmation = [];

    /**
     * @var bool
     */
    protected $wasSignedAtConstruction = false;

    /**
     * @var string|null
     */
    protected $signatureMethod;

    /**
     * @var \SAML2\XML\saml\Conditions|null
     */
    protected $conditions;


    /**
     * Constructor for SAML 2 assertions.
     *
     * @param \DOMElement|null $xml The input assertion.
     * @throws \Exception
     */
    public function __construct(DOMElement $xml = null)
    {
        $this->id = Utils::getContainer()->generateId();
        $this->issueInstant = Temporal::getTime();
        $this->authnInstant = Temporal::getTime();

        if ($xml === null) {
            return;
        }

        if (!$xml->hasAttribute('ID')) {
            throw new Exception('Missing ID attribute on SAML assertion.');
        }
        $this->id = $xml->getAttribute('ID');

        if ($xml->getAttribute('Version') !== '2.0') {
            /* Currently a very strict check. */
            throw new Exception('Unsupported version: ' . $xml->getAttribute('Version'));
        }

        $this->issueInstant = Utils::xsDateTimeToTimestamp($xml->getAttribute('IssueInstant'));

        $issuer = Issuer::getChildrenOfClass($xml);
        Assert::minCount($issuer, 1, 'Missing <saml:Issuer> in assertion.');
        $this->issuer = $issuer[0];

        $subject = Subject::getChildrenOfClass($xml);
        Assert::maxCount($subject, 1, 'More than one <saml:Subject> in <saml:Assertion>');
        $this->subject = array_pop($subject);

        $conditions = Conditions::getChildrenOfClass($xml);
        Assert::maxCount($conditions, 1, 'More than one <saml:Conditions> in <saml:Assertion>.');
        $this->conditions = array_pop($conditions);

        $this->parseAuthnStatement($xml);
        $this->parseAttributes($xml);
        $this->parseEncryptedAttributes($xml);
        $this->parseSignature($xml);
    }


    /**
     * Collect the value of the subject
     *
     * @return \SAML2\XML\saml\Subject
     */
    public function getSubject(): Subject
    {
        return $this->subject;
    }


    /**
     * Set the value of the subject-property
     * @param \SAML2\XML\saml\Subject $subject
     *
     * @return void
     */
    public function setSubject(Subject $subject): void
    {
        $this->subject = $subject;
    }


    /**
     * Collect the value of the conditions-property
     *
     * @return \SAML2\XML\saml\Conditions|null
     */
    public function getConditions(): ?Conditions
    {
        return $this->conditions;
    }


    /**
     * Set the value of the conditions-property
     * @param \SAML2\XML\saml\Conditions|null $conditions
     *
     * @return void
     */
    public function setConditions(?Conditions $conditions): void
    {
        $this->conditions = $conditions;
    }

    
    /**
     * Parse AuthnStatement in assertion.
     *
     * @param \DOMElement $xml The assertion XML element.
     * @throws \Exception
     * @return void
     */
    private function parseAuthnStatement(DOMElement $xml): void
    {
        /** @var \DOMElement[] $authnStatements */
        $authnStatements = Utils::xpQuery($xml, './saml_assertion:AuthnStatement');
        if (empty($authnStatements)) {
            $this->authnInstant = null;

            return;
        } elseif (count($authnStatements) > 1) {
            throw new Exception('More than one <saml:AuthnStatement> in <saml:Assertion> not supported.');
        }
        $authnStatement = $authnStatements[0];

        if (!$authnStatement->hasAttribute('AuthnInstant')) {
            throw new Exception('Missing required AuthnInstant attribute on <saml:AuthnStatement>.');
        }
        $this->authnInstant = Utils::xsDateTimeToTimestamp($authnStatement->getAttribute('AuthnInstant'));

        if ($authnStatement->hasAttribute('SessionNotOnOrAfter')) {
            $this->sessionNotOnOrAfter = Utils::xsDateTimeToTimestamp(
                $authnStatement->getAttribute('SessionNotOnOrAfter')
            );
        }

        if ($authnStatement->hasAttribute('SessionIndex')) {
            $this->sessionIndex = $authnStatement->getAttribute('SessionIndex');
        }

        $this->parseAuthnContext($authnStatement);
    }


    /**
     * Parse AuthnContext in AuthnStatement.
     *
     * @param \DOMElement $authnStatementEl
     * @throws \Exception
     * @return void
     */
    private function parseAuthnContext(DOMElement $authnStatementEl): void
    {
        // Get the AuthnContext element
        /** @var \DOMElement[] $authnContexts */
        $authnContexts = Utils::xpQuery($authnStatementEl, './saml_assertion:AuthnContext');
        if (count($authnContexts) > 1) {
            throw new Exception('More than one <saml:AuthnContext> in <saml:AuthnStatement>.');
        } elseif (empty($authnContexts)) {
            throw new Exception('Missing required <saml:AuthnContext> in <saml:AuthnStatement>.');
        }
        $authnContextEl = $authnContexts[0];

        // Get the AuthnContextDeclRef (if available)
        /** @var \DOMElement[] $authnContextDeclRefs */
        $authnContextDeclRefs = Utils::xpQuery($authnContextEl, './saml_assertion:AuthnContextDeclRef');
        if (count($authnContextDeclRefs) > 1) {
            throw new Exception(
                'More than one <saml:AuthnContextDeclRef> found?'
            );
        } elseif (count($authnContextDeclRefs) === 1) {
            $this->setAuthnContextDeclRef(trim($authnContextDeclRefs[0]->textContent));
        }

        // Get the AuthnContextDecl (if available)
        /** @var \DOMElement[] $authnContextDecls */
        $authnContextDecls = Utils::xpQuery($authnContextEl, './saml_assertion:AuthnContextDecl');
        if (count($authnContextDecls) > 1) {
            throw new Exception(
                'More than one <saml:AuthnContextDecl> found?'
            );
        } elseif (count($authnContextDecls) === 1) {
            $this->setAuthnContextDecl(new Chunk($authnContextDecls[0]));
        }

        // Get the AuthnContextClassRef (if available)
        /** @var \DOMElement[] $authnContextClassRefs */
        $authnContextClassRefs = Utils::xpQuery($authnContextEl, './saml_assertion:AuthnContextClassRef');
        if (count($authnContextClassRefs) > 1) {
            throw new Exception('More than one <saml:AuthnContextClassRef> in <saml:AuthnContext>.');
        } elseif (count($authnContextClassRefs) === 1) {
            $this->setAuthnContextClassRef(trim($authnContextClassRefs[0]->textContent));
        }

        // Constraint from XSD: MUST have one of the three
        if (empty($this->authnContextClassRef) && empty($this->authnContextDecl) && empty($this->authnContextDeclRef)) {
            throw new Exception(
                'Missing either <saml:AuthnContextClassRef> or <saml:AuthnContextDeclRef> or <saml:AuthnContextDecl>'
            );
        }

        $this->AuthenticatingAuthority = Utils::extractStrings(
            $authnContextEl,
            Constants::NS_SAML,
            'AuthenticatingAuthority'
        );
    }


    /**
     * Parse attribute statements in assertion.
     *
     * @param \DOMElement $xml The XML element with the assertion.
     * @throws \Exception
     * @return void
     */
    private function parseAttributes(DOMElement $xml): void
    {
        $firstAttribute = true;
        /** @var \DOMElement[] $attributes */
        $attributes = Utils::xpQuery($xml, './saml_assertion:AttributeStatement/saml_assertion:Attribute');
        foreach ($attributes as $attribute) {
            if (!$attribute->hasAttribute('Name')) {
                throw new Exception('Missing name on <saml:Attribute> element.');
            }
            $name = $attribute->getAttribute('Name');

            if ($attribute->hasAttribute('NameFormat')) {
                $nameFormat = $attribute->getAttribute('NameFormat');
            } else {
                $nameFormat = Constants::NAMEFORMAT_UNSPECIFIED;
            }

            if ($firstAttribute) {
                $this->nameFormat = $nameFormat;
                $firstAttribute = false;
            } else {
                if ($this->nameFormat !== $nameFormat) {
                    $this->nameFormat = Constants::NAMEFORMAT_UNSPECIFIED;
                }
            }

            if (!array_key_exists($name, $this->attributes)) {
                $this->attributes[$name] = [];
                $this->attributesValueTypes[$name] = [];
            }

            $this->parseAttributeValue($attribute, $name);
        }
    }


    /**
     * @param \DOMNode $attribute
     * @param string   $attributeName
     * @return void
     */
    private function parseAttributeValue(DOMNode $attribute, string $attributeName): void
    {
        /** @var \DOMElement[] $values */
        $values = Utils::xpQuery($attribute, './saml_assertion:AttributeValue');

        if ($attributeName === Constants::EPTI_URN_MACE || $attributeName === Constants::EPTI_URN_OID) {
            foreach ($values as $index => $eptiAttributeValue) {
                /** @var \DOMElement[] $eptiNameId */
                $eptiNameId = Utils::xpQuery($eptiAttributeValue, './saml_assertion:NameID');

                if (count($eptiNameId) === 1) {
                    $this->attributes[$attributeName][] = NameID::fromXML($eptiNameId[0]);
                } else {
                    /* Fall back for legacy IdPs sending string value (e.g. SSP < 1.15) */
                    Utils::getContainer()->getLogger()->warning(
                        sprintf("Attribute %s (EPTI) value %d is not an XML NameId", $attributeName, $index)
                    );
                    $nameId = new NameID($eptiAttributeValue->textContent);
                    $this->attributes[$attributeName][] = $nameId;
                }
            }

            return;
        }

        foreach ($values as $value) {
            $hasNonTextChildElements = false;
            foreach ($value->childNodes as $childNode) {
                /** @var \DOMNode $childNode */
                if ($childNode->nodeType !== XML_TEXT_NODE) {
                    $hasNonTextChildElements = true;
                    break;
                }
            }

            $type = $value->getAttribute('xsi:type');
            if ($type === '') {
                $type = null;
            }
            $this->attributesValueTypes[$attributeName][] = $type;

            if ($hasNonTextChildElements) {
                $this->attributes[$attributeName][] = $value->childNodes;
                continue;
            }

            if ($type === 'xs:integer') {
                $this->attributes[$attributeName][] = intval($value->textContent);
            } else {
                $this->attributes[$attributeName][] = trim($value->textContent);
            }
        }
    }


    /**
     * Parse encrypted attribute statements in assertion.
     *
     * @param \DOMElement $xml The XML element with the assertion.
     * @return void
     */
    private function parseEncryptedAttributes(DOMElement $xml): void
    {
        /** @var \DOMElement[] encryptedAttributes */
        $this->encryptedAttributes = Utils::xpQuery(
            $xml,
            './saml_assertion:AttributeStatement/saml_assertion:EncryptedAttribute'
        );
    }


    /**
     * Parse signature on assertion.
     *
     * @param \DOMElement $xml The assertion XML element.
     * @return void
     */
    private function parseSignature(DOMElement $xml): void
    {
        /** @var \DOMAttr[] $signatureMethod */
        $signatureMethod = Utils::xpQuery($xml, './ds:Signature/ds:SignedInfo/ds:SignatureMethod/@Algorithm');

        /* Validate the signature element of the message. */
        $sig = Utils::validateElement($xml);
        if ($sig !== false) {
            $this->wasSignedAtConstruction = true;
            $this->setCertificates($sig['Certificates']);
            $this->setSignatureData($sig);
            $this->setSignatureMethod($signatureMethod[0]->value);
        }
    }


    /**
     * Validate this assertion against a public key.
     *
     * If no signature was present on the assertion, we will return false.
     * Otherwise, true will be returned. An exception is thrown if the
     * signature validation fails.
     *
     * @param  XMLSecurityKey $key The key we should check against.
     * @return boolean        true if successful, false if it is unsigned.
     *
     * @throws \InvalidArgumentException if assertions are false
     */
    public function validate(XMLSecurityKey $key): bool
    {
        Assert::same($key->type, XMLSecurityKey::RSA_SHA256);

        if ($this->signatureData === null) {
            return false;
        }

        Utils::validateSignature($this->signatureData, $key);

        return true;
    }


    /**
     * Retrieve the identifier of this assertion.
     *
     * @return string The identifier of this assertion.
     */
    public function getId(): string
    {
        return $this->id;
    }


    /**
     * Set the identifier of this assertion.
     *
     * @param string $id The new identifier of this assertion.
     * @return void
     */
    public function setId(string $id): void
    {
        $this->id = $id;
    }


    /**
     * Retrieve the issue timestamp of this assertion.
     *
     * @return int The issue timestamp of this assertion, as an UNIX timestamp.
     */
    public function getIssueInstant(): int
    {
        return $this->issueInstant;
    }


    /**
     * Set the issue timestamp of this assertion.
     *
     * @param int $issueInstant The new issue timestamp of this assertion, as an UNIX timestamp.
     * @return void
     */
    public function setIssueInstant(int $issueInstant): void
    {
        $this->issueInstant = $issueInstant;
    }


    /**
     * Retrieve the issuer if this assertion.
     *
     * @return \SAML2\XML\saml\Issuer The issuer of this assertion.
     */
    public function getIssuer(): Issuer
    {
        return $this->issuer;
    }


    /**
     * Set the issuer of this message.
     *
     * @param \SAML2\XML\saml\Issuer $issuer The new issuer of this assertion.
     * @return void
     */
    public function setIssuer(Issuer $issuer): void
    {
        $this->issuer = $issuer;
    }


    /**
     * Did this Assertion contain encrypted Attributes?
     *
     * @return bool
     */
    public function hasEncryptedAttributes(): bool
    {
        return $this->encryptedAttributes !== [];
    }


    /**
     * Decrypt the assertion attributes.
     *
     * @param XMLSecurityKey $key
     * @param array $blacklist
     * @throws \Exception
     * @return void
     */
    public function decryptAttributes(XMLSecurityKey $key, array $blacklist = []): void
    {
        if (!$this->hasEncryptedAttributes()) {
            return;
        }
        $firstAttribute = true;
        $attributes = $this->getEncryptedAttributes();
        foreach ($attributes as $attributeEnc) {
            /* Decrypt node <EncryptedAttribute> */
            $attribute = Utils::decryptElement(
                $attributeEnc->getElementsByTagName('EncryptedData')->item(0),
                $key,
                $blacklist
            );

            if (!$attribute->hasAttribute('Name')) {
                throw new Exception('Missing name on <saml:Attribute> element.');
            }
            $name = $attribute->getAttribute('Name');

            if ($attribute->hasAttribute('NameFormat')) {
                $nameFormat = $attribute->getAttribute('NameFormat');
            } else {
                $nameFormat = Constants::NAMEFORMAT_UNSPECIFIED;
            }

            if ($firstAttribute) {
                $this->nameFormat = $nameFormat;
                $firstAttribute = false;
            } else {
                if ($this->nameFormat !== $nameFormat) {
                    $this->nameFormat = Constants::NAMEFORMAT_UNSPECIFIED;
                }
            }

            if (!array_key_exists($name, $this->attributes)) {
                $this->attributes[$name] = [];
            }

            $this->parseAttributeValue($attribute, $name);
        }
    }

    /**
     * Retrieve $requiredEncAttributes if attributes will be send encrypted
     *
     * @return bool True to encrypt attributes in the assertion.
     */
    public function getRequiredEncAttributes(): bool
    {
        return $this->requiredEncAttributes;
    }


    /**
     * Set $requiredEncAttributes if attributes will be send encrypted
     *
     * @param bool $ea true to encrypt attributes in the assertion.
     * @return void
     */
    public function setRequiredEncAttributes(bool $ea): void
    {
        $this->requiredEncAttributes = $ea;
    }


    /**
     * Retrieve the AuthnInstant of the assertion.
     *
     * @return int|null The timestamp the user was authenticated, or NULL if the user isn't authenticated.
     */
    public function getAuthnInstant(): ?int
    {
        return $this->authnInstant;
    }


    /**
     * Set the AuthnInstant of the assertion.
     *
     * @param int|null $authnInstant Timestamp the user was authenticated, or NULL if we don't want an AuthnStatement.
     * @return void
     */
    public function setAuthnInstant(?int $authnInstant): void
    {
        $this->authnInstant = $authnInstant;
    }


    /**
     * Retrieve the session expiration timestamp.
     *
     * This function returns null if there are no restrictions on the
     * session lifetime.
     *
     * @return int|null The latest timestamp this session is valid.
     */
    public function getSessionNotOnOrAfter(): ?int
    {
        return $this->sessionNotOnOrAfter;
    }


    /**
     * Set the session expiration timestamp.
     *
     * Set this to null if no limit is required.
     *
     * @param int|null $sessionNotOnOrAfter The latest timestamp this session is valid.
     * @return void
     */
    public function setSessionNotOnOrAfter(int $sessionNotOnOrAfter = null): void
    {
        $this->sessionNotOnOrAfter = $sessionNotOnOrAfter;
    }


    /**
     * Retrieve the session index of the user at the IdP.
     *
     * @return string|null The session index of the user at the IdP.
     */
    public function getSessionIndex(): ?string
    {
        return $this->sessionIndex;
    }


    /**
     * Set the session index of the user at the IdP.
     *
     * Note that the authentication context must be set before the
     * session index can be inluded in the assertion.
     *
     * @param string|null $sessionIndex The session index of the user at the IdP.
     * @return void
     */
    public function setSessionIndex(string $sessionIndex = null): void
    {
        $this->sessionIndex = $sessionIndex;
    }


    /**
     * Retrieve the authentication method used to authenticate the user.
     *
     * This will return null if no authentication statement was
     * included in the assertion.
     *
     * @return string|null The authentication method.
     */
    public function getAuthnContextClassRef(): ?string
    {
        return $this->authnContextClassRef;
    }


    /**
     * Set the authentication method used to authenticate the user.
     *
     * If this is set to null, no authentication statement will be
     * included in the assertion. The default is null.
     *
     * @param string|null $authnContextClassRef The authentication method.
     * @return void
     */
    public function setAuthnContextClassRef(string $authnContextClassRef = null): void
    {
        $this->authnContextClassRef = $authnContextClassRef;
    }


    /**
     * Retrieve the signature method.
     *
     * @return string|null The signature method.
     */
    public function getSignatureMethod(): ?string
    {
        return $this->signatureMethod;
    }


    /**
     * Set the signature method used.
     *
     * @param string|null $signatureMethod
     * @return void
     */
    public function setSignatureMethod(string $signatureMethod = null): void
    {
        $this->signatureMethod = $signatureMethod;
    }


    /**
     * Set the authentication context declaration.
     *
     * @param \SAML2\XML\Chunk $authnContextDecl
     * @throws \Exception
     * @return void
     */
    public function setAuthnContextDecl(Chunk $authnContextDecl): void
    {
        if (!empty($this->authnContextDeclRef)) {
            throw new Exception(
                'AuthnContextDeclRef is already registered! May only have either a Decl or a DeclRef, not both!'
            );
        }

        $this->authnContextDecl = $authnContextDecl;
    }


    /**
     * Get the authentication context declaration.
     *
     * See:
     * @url http://docs.oasis-open.org/security/saml/v2.0/saml-authn-context-2.0-os.pdf
     *
     * @return \SAML2\XML\Chunk|null
     */
    public function getAuthnContextDecl(): ?Chunk
    {
        return $this->authnContextDecl;
    }


    /**
     * Set the authentication context declaration reference.
     *
     * @param string|null $authnContextDeclRef
     * @throws \Exception
     * @return void
     */
    public function setAuthnContextDeclRef(string $authnContextDeclRef = null): void
    {
        if (!empty($this->authnContextDecl)) {
            throw new Exception(
                'AuthnContextDecl is already registered! May only have either a Decl or a DeclRef, not both!'
            );
        }

        $this->authnContextDeclRef = $authnContextDeclRef;
    }


    /**
     * Get the authentication context declaration reference.
     * URI reference that identifies an authentication context declaration.
     *
     * The URI reference MAY directly resolve into an XML document containing the referenced declaration.
     *
     * @return string|null
     */
    public function getAuthnContextDeclRef(): ?string
    {
        return $this->authnContextDeclRef;
    }


    /**
     * Retrieve the AuthenticatingAuthority.
     *
     * @return array
     */
    public function getAuthenticatingAuthority(): array
    {
        return $this->AuthenticatingAuthority;
    }


    /**
     * Set the AuthenticatingAuthority
     *
     * @param array $authenticatingAuthority
     * @return void
     */
    public function setAuthenticatingAuthority(array $authenticatingAuthority): void
    {
        $this->AuthenticatingAuthority = $authenticatingAuthority;
    }


    /**
     * Retrieve all attributes.
     *
     * @return array All attributes, as an associative array.
     */
    public function getAttributes(): array
    {
        return $this->attributes;
    }


    /**
     * Replace all attributes.
     *
     * @param array $attributes All new attributes, as an associative array.
     * @return void
     */
    public function setAttributes(array $attributes): void
    {
        $this->attributes = $attributes;
    }

    /**
     * @return array|null
     */
    public function getSignatureData(): ?array
    {
        return $this->signatureData;
    }


    /**
     * @param array|null $signatureData
     * @return void
     */
    public function setSignatureData(array $signatureData = null): void
    {
        $this->signatureData = $signatureData;
    }


    /**
     * Retrieve all attributes value types.
     *
     * @return array All attributes value types, as an associative array.
     */
    public function getAttributesValueTypes(): array
    {
        return $this->attributesValueTypes;
    }


    /**
     * Replace all attributes value types..
     *
     * @param array $attributesValueTypes All new attribute value types, as an associative array.
     * @return void
     */
    public function setAttributesValueTypes(array $attributesValueTypes): void
    {
        $this->attributesValueTypes = $attributesValueTypes;
    }


    /**
     * Retrieve the NameFormat used on all attributes.
     *
     * If more than one NameFormat is used in the received attributes, this
     * returns the unspecified NameFormat.
     *
     * @return string The NameFormat used on all attributes.
     */
    public function getAttributeNameFormat(): string
    {
        return $this->nameFormat;
    }


    /**
     * Set the NameFormat used on all attributes.
     *
     * @param string $nameFormat The NameFormat used on all attributes.
     * @return void
     */
    public function setAttributeNameFormat(string $nameFormat): void
    {
        $this->nameFormat = $nameFormat;
    }


    /**
     * Retrieve the SubjectConfirmation elements we have in our Subject element.
     *
     * @return array Array of \SAML2\XML\saml\SubjectConfirmation elements.
     */
    public function getSubjectConfirmation(): array
    {
        return $this->SubjectConfirmation;
    }


    /**
     * Set the SubjectConfirmation elements that should be included in the assertion.
     *
     * @param array $SubjectConfirmation Array of \SAML2\XML\saml\SubjectConfirmation elements.
     * @return void
     */
    public function setSubjectConfirmation(array $SubjectConfirmation): void
    {
        $this->SubjectConfirmation = $SubjectConfirmation;
    }


    /**
     * Retrieve the encryptedAttributes elements we have.
     *
     * @return array Array of \DOMElement elements.
     */
    public function getEncryptedAttributes(): array
    {
        return $this->encryptedAttributes;
    }


    /**
     * Set the encryptedAttributes elements
     *
     * @param array $encAttrs Array of \DOMElement elements.
     * @return void
     */
    public function setEncryptedAttributes(array $encAttrs): void
    {
        $this->encryptedAttributes = $encAttrs;
    }


    /**
     * Return the key we should use to encrypt the assertion.
     *
     * @return XMLSecurityKey|null The key, or NULL if no key is specified..
     *
     */
    public function getEncryptionKey(): ?XMLSecurityKey
    {
        return $this->encryptionKey;
    }


    /**
     * Set the private key we should use to encrypt the attributes.
     *
     * @param XMLSecurityKey|null $Key
     * @return void
     */
    public function setEncryptionKey(XMLSecurityKey $Key = null): void
    {
        $this->encryptionKey = $Key;
    }


    /**
     * Set the certificates that should be included in the assertion.
     *
     * The certificates should be strings with the PEM encoded data.
     *
     * @param string[] $certificates An array of certificates.
     * @return void
     */
    public function setCertificates(array $certificates): void
    {
        $this->certificates = $certificates;
    }


    /**
     * Retrieve the certificates that are included in the assertion.
     *
     * @return string[] An array of certificates.
     */
    public function getCertificates(): array
    {
        return $this->certificates;
    }


    /**
     * @return bool
     */
    public function wasSignedAtConstruction(): bool
    {
        return $this->wasSignedAtConstruction;
    }


    /**
     * Convert this assertion to an XML element.
     *
     * @param  \DOMElement|null $parentElement The DOM node the assertion should be created in.
     * @return \DOMElement   This assertion.
     *
     * @throws \InvalidArgumentException if assertions are false
     */
    public function toXML(DOMElement $parentElement = null): DOMElement
    {
        Assert::notEmpty($this->issuer, 'Cannot convert Assertion to XML without an Issuer set.');

        if ($parentElement === null) {
            $document = DOMDocumentFactory::create();
            $parentElement = $document;
        } else {
            $document = $parentElement->ownerDocument;
        }

        $root = $document->createElementNS(Constants::NS_SAML, 'saml:' . 'Assertion');
        $parentElement->appendChild($root);

        /* Ugly hack to add another namespace declaration to the root element. */
        $root->setAttributeNS(Constants::NS_SAMLP, 'samlp:tmp', 'tmp');
        $root->removeAttributeNS(Constants::NS_SAMLP, 'tmp');
        $root->setAttributeNS(Constants::NS_XSI, 'xsi:tmp', 'tmp');
        $root->removeAttributeNS(Constants::NS_XSI, 'tmp');
        $root->setAttributeNS(Constants::NS_XS, 'xs:tmp', 'tmp');
        $root->removeAttributeNS(Constants::NS_XS, 'tmp');

        $root->setAttribute('ID', $this->id);
        $root->setAttribute('Version', '2.0');
        $root->setAttribute('IssueInstant', gmdate('Y-m-d\TH:i:s\Z', $this->issueInstant));

        $issuer = $this->issuer->toXML($root);

        if ($this->subject !== null) {
            $this->subject->toXML($root);
        }

        if ($this->conditions !== null) {
            $this->conditions->toXML($root);
        }

        $this->addAuthnStatement($root);
        if ($this->getRequiredEncAttributes() === false) {
            $this->addAttributeStatement($root);
        } else {
            $this->addEncryptedAttributeStatement($root);
        }

        if ($this->signingKey !== null) {
            Utils::insertSignature($this->signingKey, $this->certificates, $root, $issuer->nextSibling);
        }

        return $root;
    }


    /**
     * Add a AuthnStatement-node to the assertion.
     *
     * @param \DOMElement $root The assertion element we should add the authentication statement to.
     * @return void
     */
    private function addAuthnStatement(DOMElement $root): void
    {
        if (
            $this->authnInstant === null
            || (
                $this->authnContextClassRef === null
                && $this->authnContextDecl === null
                && $this->authnContextDeclRef === null
            )
        ) {
            /* No authentication context or AuthnInstant => no authentication statement. */

            return;
        }

        $document = $root->ownerDocument;

        $authnStatementEl = $document->createElementNS(Constants::NS_SAML, 'saml:AuthnStatement');
        $root->appendChild($authnStatementEl);

        $authnStatementEl->setAttribute('AuthnInstant', gmdate('Y-m-d\TH:i:s\Z', $this->authnInstant));

        if ($this->sessionNotOnOrAfter !== null) {
            $authnStatementEl->setAttribute(
                'SessionNotOnOrAfter',
                gmdate('Y-m-d\TH:i:s\Z', $this->sessionNotOnOrAfter)
            );
        }
        if ($this->sessionIndex !== null) {
            $authnStatementEl->setAttribute('SessionIndex', $this->sessionIndex);
        }

        $authnContextEl = $document->createElementNS(Constants::NS_SAML, 'saml:AuthnContext');
        $authnStatementEl->appendChild($authnContextEl);

        if (!empty($this->authnContextClassRef)) {
            Utils::addString(
                $authnContextEl,
                Constants::NS_SAML,
                'saml:AuthnContextClassRef',
                $this->authnContextClassRef
            );
        }
        if (!empty($this->authnContextDecl)) {
            $this->authnContextDecl->toXML($authnContextEl);
        }
        if (!empty($this->authnContextDeclRef)) {
            Utils::addString(
                $authnContextEl,
                Constants::NS_SAML,
                'saml:AuthnContextDeclRef',
                $this->authnContextDeclRef
            );
        }

        Utils::addStrings(
            $authnContextEl,
            Constants::NS_SAML,
            'saml:AuthenticatingAuthority',
            false,
            $this->AuthenticatingAuthority
        );
    }


    /**
     * Add an AttributeStatement-node to the assertion.
     *
     * @param \DOMElement $root The assertion element we should add the subject to.
     * @return void
     */
    private function addAttributeStatement(DOMElement $root): void
    {
        if (empty($this->attributes)) {
            return;
        }

        $document = $root->ownerDocument;

        $attributeStatement = $document->createElementNS(Constants::NS_SAML, 'saml:AttributeStatement');
        $root->appendChild($attributeStatement);

        foreach ($this->attributes as $name => $values) {
            $attribute = $document->createElementNS(Constants::NS_SAML, 'saml:Attribute');
            $attributeStatement->appendChild($attribute);
            $attribute->setAttribute('Name', $name);

            if ($this->nameFormat !== Constants::NAMEFORMAT_UNSPECIFIED) {
                $attribute->setAttribute('NameFormat', $this->nameFormat);
            }

            // make sure eduPersonTargetedID can be handled properly as a NameID
            if ($name === Constants::EPTI_URN_MACE || $name === Constants::EPTI_URN_OID) {
                foreach ($values as $eptiValue) {
                    $attributeValue = $document->createElementNS(Constants::NS_SAML, 'saml:AttributeValue');
                    $attribute->appendChild($attributeValue);
                    if ($eptiValue instanceof NameID) {
                        $eptiValue->toXML($attributeValue);
                    } elseif ($eptiValue instanceof DOMNodeList) {
                        /** @var \DOMElement $value */
                        $value = $eptiValue->item(0);
                        $node = $root->ownerDocument->importNode($value, true);
                        $attributeValue->appendChild($node);
                    } else {
                        $attributeValue->textContent = $eptiValue;
                    }
                }

                continue;
            }

            // get value type(s) for the current attribute
            if (array_key_exists($name, $this->attributesValueTypes)) {
                $valueTypes = $this->attributesValueTypes[$name];
                if (is_array($valueTypes) && count($valueTypes) != count($values)) {
                    throw new \Exception('Array of value types and array of values have different size for attribute ' .
                        var_export($name, true));
                }
            } else {
                // if no type(s), default behaviour
                $valueTypes = null;
            }

            $vidx = -1;
            foreach ($values as $value) {
                $vidx++;

                // try to get type from current types
                $type = null;
                if (!is_null($valueTypes)) {
                    if (is_array($valueTypes)) {
                        $type = $valueTypes[$vidx];
                    } else {
                        $type = $valueTypes;
                    }
                }

                // if no type get from types, use default behaviour
                if (is_null($type)) {
                    if (is_string($value)) {
                        $type = 'xs:string';
                    } elseif (is_int($value)) {
                        $type = 'xs:integer';
                    } else {
                        $type = null;
                    }
                }

                $attributeValue = $document->createElementNS(Constants::NS_SAML, 'saml:AttributeValue');
                $attribute->appendChild($attributeValue);
                if ($type !== null) {
                    $attributeValue->setAttributeNS(Constants::NS_XSI, 'xsi:type', $type);
                }
                if (is_null($value)) {
                    $attributeValue->setAttributeNS(Constants::NS_XSI, 'xsi:nil', 'true');
                }

                if ($value instanceof \DOMNodeList) {
                    foreach ($value as $v) {
                        $node = $document->importNode($v, true);
                        $attributeValue->appendChild($node);
                    }
                } else {
                    $value = strval($value);
                    $attributeValue->appendChild($document->createTextNode($value));
                }
            }
        }
    }


    /**
     * Add an EncryptedAttribute Statement-node to the assertion.
     *
     * @param \DOMElement $root The assertion element we should add the Encrypted Attribute Statement to.
     * @return void
     *
     * @throws \InvalidArgumentException if assertions are false
     */
    private function addEncryptedAttributeStatement(DOMElement $root): void
    {
        if ($this->getRequiredEncAttributes() === false) {
            return;
        }
        Assert::notNull($this->encryptionKey);

        $document = $root->ownerDocument;

        $attributeStatement = $document->createElementNS(Constants::NS_SAML, 'saml:AttributeStatement');
        $root->appendChild($attributeStatement);

        foreach ($this->attributes as $name => $values) {
            $document2 = DOMDocumentFactory::create();
            $attribute = $document2->createElementNS(Constants::NS_SAML, 'saml:Attribute');
            $attribute->setAttribute('Name', $name);
            $document2->appendChild($attribute);

            if ($this->nameFormat !== Constants::NAMEFORMAT_UNSPECIFIED) {
                $attribute->setAttribute('NameFormat', $this->getAttributeNameFormat());
            }

            foreach ($values as $value) {
                if (is_string($value)) {
                    $type = 'xs:string';
                } elseif (is_int($value)) {
                    $type = 'xs:integer';
                } else {
                    $type = null;
                }

                $attributeValue = $document2->createElementNS(Constants::NS_SAML, 'saml:AttributeValue');
                $attribute->appendChild($attributeValue);
                if ($type !== null) {
                    $attributeValue->setAttributeNS(Constants::NS_XSI, 'xsi:type', $type);
                }

                if ($value instanceof DOMNodeList) {
                    foreach ($value as $v) {
                        $node = $document2->importNode($v, true);
                        $attributeValue->appendChild($node);
                    }
                } else {
                    $value = strval($value);
                    $attributeValue->appendChild($document2->createTextNode($value));
                }
            }
            /*Once the attribute nodes are built, the are encrypted*/
            $EncAssert = new XMLSecEnc();
            $EncAssert->setNode($document2->documentElement);
            $EncAssert->type = 'http://www.w3.org/2001/04/xmlenc#Element';
            /*
             * Attributes are encrypted with a session key and this one with
             * $EncryptionKey
             */
            $symmetricKey = new XMLSecurityKey(XMLSecurityKey::AES256_CBC);
            $symmetricKey->generateSessionKey();
            /** @psalm-suppress PossiblyNullArgument */
            $EncAssert->encryptKey($this->encryptionKey, $symmetricKey);
            /** @psalm-suppress UndefinedClass */
            $EncrNode = $EncAssert->encryptNode($symmetricKey);

            $EncAttribute = $document->createElementNS(Constants::NS_SAML, 'saml:EncryptedAttribute');
            $attributeStatement->appendChild($EncAttribute);
            /** @psalm-suppress InvalidArgument */
            $n = $document->importNode($EncrNode, true);
            $EncAttribute->appendChild($n);
        }
    }
}
