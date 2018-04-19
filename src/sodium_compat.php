<?php

if (!\defined('SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES')) {
    \define('SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES', \Sodium\CRYPTO_SIGN_PUBLICKEYBYTES);
}

if (!\defined('SODIUM_CRYPTO_SIGN_BYTES')) {
    \define('SODIUM_CRYPTO_SIGN_BYTES', \Sodium\CRYPTO_SIGN_BYTES);
}

if (!\is_callable('sodium_crypto_sign_publickey')) {
    /**
     * @param string $keypair
     *
     * @return string
     */
    function sodium_crypto_sign_publickey($keypair)
    {
        return \Sodium\crypto_sign_publickey($keypair);
    }
}

if (!\is_callable('sodium_crypto_sign_secretkey')) {
    /**
     * @param string $keypair
     *
     * @return string
     */
    function sodium_crypto_sign_secretkey($keypair)
    {
        return \Sodium\crypto_sign_secretkey($keypair);
    }
}

if (!\is_callable('sodium_crypto_sign_detached')) {
    /**
     * @param string $message
     * @param string $sk
     *
     * @return string
     */
    function sodium_crypto_sign_detached($message, $sk)
    {
        return \Sodium\crypto_sign_detached($message, $sk);
    }
}

if (!\is_callable('sodium_crypto_sign_verify_detached')) {
    /**
     * @param string $signature
     * @param string $message
     * @param string $pk
     *
     * @return bool
     */
    function sodium_crypto_sign_verify_detached($signature, $message, $pk)
    {
        return \Sodium\crypto_sign_verify_detached($signature, $message, $pk);
    }
}

if (!\is_callable('sodium_crypto_sign_keypair')) {
    /**
     * @return string
     */
    function sodium_crypto_sign_keypair()
    {
        return \Sodium\crypto_sign_keypair();
    }
}
