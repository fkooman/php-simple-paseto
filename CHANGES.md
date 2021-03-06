# ChangeLog

## 0.3.1 (2018-10-08)
- implement `AsymmetricPublicKey::getKid()`

## 0.3.0 (2018-10-07)
- implement `AsymmetricSecretKey` and `AsymmetricPublicKey` very similar to 
  `paragonie/paseto`
- `KeyPair` no longer exists
- Keys are now in the `fkooman\Paseto\Keys` namespace

## 0.2.1 (2018-09-28)
- use symfony/polyfill-php70 instead of error_polyfill

## 0.2.0 (2018-09-28)
- introduce `KeyPair`, `SecretKey` and `PublicKey` objects
- throw `TypeError` when type of parameters is wrong

## 0.1.7 (2018-08-09)
- make sure we only support 64 bit PHP >= 5.4, we don't care about 32 bit 
  anymore
- cleanup `Version2::intToByteArray`
- update README
- update `psalm.xml` file

## 0.1.6 (2018-05-01)
- support `paragonie/constant_time_encoding` with and without encodeUnpadded

## 0.1.5 (2018-04-24)
- remove some dead code in tests
- update DocBlock exception documentation
- add usage to README.md

## 0.1.4 (2018-04-23)
- simplify cleanup

## 0.1.3 (2018-04-20)
- make it possible to not care about footer when verifying
- rename `Version2::getFooter` to `Version2::extractFooter`

## 0.1.2 (2018-04-19)
- fix for PHP < 5.6.3

## 0.1.1 (2018-04-19)
- update `composer.json`

## 0.1.0 (2018-04-19)
- initial release
