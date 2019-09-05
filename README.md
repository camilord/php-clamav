# php-clamav
PHP library to scan file for viruses using ClamAV

# installing ClamAV as pre-requisite for the package php-clamav

for ubuntu/debian:
```$bash
sudo apt install -y clamav
```

for redhat/centos/fedora:
```$bash
sudo yum install -y clamav
```

# Installing the library
```
{
    "require": {
        "camilord/php-clamav": "*"
    }
}
```

or 

```
composer require camilord/php-clamav
```