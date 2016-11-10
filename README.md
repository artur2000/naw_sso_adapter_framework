# Direct SSO adapter framework
Small framework to create Direct SSO adapters (http://www.single-signon.com/) in a much cleaner way as it has been done with the original adapters.

This framework does not provide all components needed to implement a signature based SSO between two applications.
For the entire SSO process to work, the original SSO agent script and configuration is needed.
Please visit the project page http://www.single-signon.com for more information.

Based on this package, the SSO adapter part of the SSO solution can be created.
It ships example SSO adapter bootstrap script for PhpBB3 inside the directory "adapters".

# Installation

Register the package repository in your composer.json.
```
"repositories": [
		{
			"type": "package",
			"package": {
				"name": "artur2000/naw-sso-adapter-framework",
				"version": "dev-master",
				"source": {
					"url": "git://github.com/artur2000/naw_sso_adapter_framework",
					"type": "git",
					"reference": "master"
				},
				"autoload": {
					"psr-0" : {
						"Q3i\\NawSso" : "src"
					}
				}
			}
		}
	]
```

Require the package
```
composer require artur2000/naw-sso-adapter-framework:dev-master
```

Now you can prepare your adapter bootstrap file simmilar to the example adapter in adapters/phpbb3.php.
Then put it into the root directory of your SSO client application and adjust Direct SSO agent configuration (see. http://www.single-signon.com).