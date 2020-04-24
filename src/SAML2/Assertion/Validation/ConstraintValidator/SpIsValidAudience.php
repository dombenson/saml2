<?php

declare(strict_types=1);

namespace SAML2\Assertion\Validation\ConstraintValidator;

use SAML2\XML\saml\Assertion;
use SAML2\Assertion\Validation\AssertionConstraintValidator;
use SAML2\Assertion\Validation\Result;
use SAML2\Configuration\ServiceProvider;
use SAML2\Configuration\ServiceProviderAware;
use Webmozart\Assert\Assert;

class SpIsValidAudience implements
    AssertionConstraintValidator,
    ServiceProviderAware
{
    /**
     * @var \SAML2\Configuration\ServiceProvider
     */
    private $serviceProvider;


    /**
     * @param ServiceProvider $serviceProvider
     * @return void
     */
    public function setServiceProvider(ServiceProvider $serviceProvider): void
    {
        $this->serviceProvider = $serviceProvider;
    }


    /**
     * @param \SAML2\XML\saml\Assertion $assertion
     * @param \SAML2\Assertion\Validation\Result $result
     * @return void
     *
     * @throws \InvalidArgumentException if assertions are false
     */
    public function validate(Assertion $assertion, Result $result): void
    {
        Assert::notEmpty($this->serviceProvider);

        $conditions = $assertion->getConditions();
        if ($conditions === null) {
            return;
        }

        $audienceRestrictions = $conditions->getAudienceRestriction();
        if (empty($audienceRestrictions)) {
            return;
        }

        $entityId = $this->serviceProvider->getEntityId();

        $all = [];
        foreach ($audienceRestrictions as $audienceRestriction) {
            $audiences = $audienceRestriction->getAudience();
            if (in_array($entityId, $audiences, true)) {
                return;
            }
            $all[] = $audiences;
        }

        $result->addError(sprintf(
            'The configured Service Provider [%s] is not a valid audience for the assertion. Audiences: [%s]',
            strval($entityId),
            var_export($all, true)
        ));
    }
}
