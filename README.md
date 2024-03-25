# ipspy.net API

The ipspy.net API is a PHP-based tool designed to offer various network-related functionalities, including public IP retrieval, WHOIS lookups, DNS record fetching, and more. This API serves as a comprehensive toolkit for developers working on projects that require network information and manipulation.

## Features

- Get the client's public IP address
- Perform DNS lookups (A, AAAA, MX, NS, CNAME, TXT records, and more)
- Execute WHOIS lookups for domain names
- Retrieve reverse DNS information for IP addresses
- Fetch geolocation information for IP addresses
- Generate random passwords with customizable parameters
- Get date and time information in various formats and timezones
- Manage UUID cookies for clients

## Installation

1. Clone this repository to your PHP server environment.
2. Ensure that your PHP version is compatible with the requirements (PHP 7.4 or newer is recommended).
3. The API does not require a database.

## Usage

### Basic Usage

To utilize the ipspy.net API, include the `ipspy_api.php` file in your project and create an instance of the `ipspy_api` class. Here's a basic example:

```php
require_once 'path/to/ipspy_api.php';

$data = [
    // Your data here
];

$ipspy_api = new ipspy_api();
$result = $ipspy_api->init($data);

echo $result;
```

### API Methods

The API supports various methods to retrieve or generate network-related information. You can specify the method you wish to use through the `$data['api_method']` parameter. Available methods include:

- `get_public_ip`: Retrieve the client's public IP address.
- `get_dns_records`: Fetch DNS records for a specified hostname.
- `get_whois_records`: Perform a WHOIS lookup for a domain.
- ...and more. Refer to the source code for a complete list of methods.

## Configuration

Before deploying the API, you may need to adjust certain configuration settings in the `ipspy_api.php` file, such as the `$file_level_array_directory` for storing array data on the filesystem.

## Contributing

Contributions are welcome! If you have a feature request, bug report, or a patch, please feel free to submit an issue or a pull request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgements

- Thanks to everyone who has contributed to the development and improvement of this API.

## Notes from Author

No Fucqs Given... 

Thanks for using ipspy.net to my valued IP Spy community!

- T (tristan@ipspy.net)
