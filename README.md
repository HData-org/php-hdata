Interact with HData servers using PHP

[![Latest Version on Packagist](https://img.shields.io/packagist/v/hdata/hdata.svg?style=flat-square)](https://packagist.org/packages/hdata/hdata)
[![Total Downloads](https://img.shields.io/packagist/dt/hdata/hdata.svg?style=flat-square)](https://packagist.org/packages/hdata/hdata)
![GitHub Actions](https://github.com/hdata-org/php-hdata/actions/workflows/main.yml/badge.svg)

See https://github.com/HData-org/hdata/tree/master/server for creating an HData server to connect this package with.

## Installation

You can install the package via composer:

```bash
composer require hdata/hdata
```

## Usage

Note: Be sure to have the php_openssl extension enabled.

```php
use HData\HData;

$host = "127.0.0.1";
$port = 8888;

$hdata = new HData\HData($host, $port);

echo $hdata->getStatus();

$hdata->disconnect();
```

### Security

If you discover any security related issues, please email ben@bunnbuns.net instead of using the issue tracker.

## License

The Apache License 2. Please see [License File](LICENSE.md) for more information.

## PHP Package Boilerplate

This package was generated using the [PHP Package Boilerplate](https://laravelpackageboilerplate.com) by [Beyond Code](http://beyondco.de/).
