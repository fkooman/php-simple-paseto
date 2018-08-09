# ChangeLog

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
