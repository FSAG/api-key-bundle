<?php

namespace Uecode\Bundle\ApiKeyBundle\Security\Core\User;

/**
 * @author Nikolai Zujev <nikolai.zujev@gmail.com>
 */
interface ApiKeyUserProviderInterface
{
    /**
     * @param string $apiKey
     * @param string $discriminator
     *
     * @return null|\Symfony\Component\Security\Core\User\UserInterface
     */
    public function loadUserByApiKey($apiKey, $discriminator = null);
}
