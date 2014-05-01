<?php

namespace Uecode\Bundle\ApiKeyBundle\Security\Core\User;

use Symfony\Component\Security\Core\User\UserInterface;

/**
 * @author Nikolai Zujev <nikolai.zujev@gmail.com>
 */
interface ApiKeyUserInterface extends UserInterface
{
    /**
     * @param string|null $discriminator
     *
     * @return string|null
     */
    public function getApiKey($discriminator = null);

    /**
     * @param string|null $discriminator
     *
     * @return boolean
     */
    public function isApiKeyEnabled($discriminator = null);

    /**
     * @param string|null $discriminator
     *
     * @return boolean
     */
    public function isApiKeyNonExpired($discriminator = null);
}
