<?php
// IP SPY API
// Break the internet in 1000 lines or less, and.... go....
// Author: Tristan McGowan, (tristan@ipspy.net) No Fucqs Given....	
class ipspy_api
{
	private $data;
	private $request_body;
	private $timezones;
	private static string $file_level_array_directory = '/static/';
    private string $api_method;
    private string $client_public_ip;
    private $special_characters;
	private array $date_time_formats;
	private array $date_time_zones;
	private array $lowercase_characters;
	private array $uppercase_characters;
	private array $numbers;
	private array $whois_servers;
	private static $timezone_to_php = [
			'GMT' => 'Europe/Dublin',
			'UTC' => 'Europe/Dublin',
			'ECT' => 'Africa/Libreville',
			'EET' => 'Africa/Tripoli',
			'ART' => 'Africa/Cairo',
			'EAT' => 'Africa/Addis_Ababa',
			'MET' => 'Asia/Baghdad',
			'NET' => 'Asia/Dubai',
			'PLT' => 'Asia/Karachi',
			'IST' => 'Asia/Kolkata',
			'BST' => 'Asia/Dhaka',
			'VST' => 'Asia/Ho_Chi_Minh',
			'CTT' => 'Asia/Taipei',
			'JST' => 'Asia/Tokyo',
			'ACT' => 'Australia/Adelaide',
			'AET' => 'Australia/Brisbane',
			'SST' => 'Pacific/Guadalcanal',
			'NST' => 'Pacific/Auckland',
			'MIT' => 'Pacific/Midway',
			'HST' => 'Pacific/Honolulu',
			'AST' => 'America/Anchorage',
			'PST' => 'Pacific/Pitcairn',
			'PNT' => 'America/Phoenix',
			'MST' => 'America/Denver',
			'CST' => 'America/Chicago',
			'EST' => 'America/New_York',
			'IET' => 'America/New_York',
			'PRT' => 'America/Puerto_Rico',
			'CNT' => 'America/Araguaina',
			'AGT' => 'America/Araguaina',
			'BET' => 'America/Fortaleza',
			'CAT' => 'Atlantic/Cape_Verde',
		];
    public function init($data)
    {
    	$this->data = $data;
    	$this->request_body = json_decode($this->data['body'], true);
    	$this->timezones =  $this->read_file_level_array('$timezones');
		$this->whois_servers =  $this->read_file_level_array('$whois_servers');
    	$this->special_characters =  $this->read_file_level_array('$special_characters');
    	$this->date_time_formats =  $this->read_file_level_array('$date_time_formats');
    	$this->set_access_control_headers();
    	$this->get_api_method();
        $this->get_client_public_ip();
        return $this->route_api_method();
    }
    private function filter_request_param_string(string $param)
    {
		if($param === "undefined")
		{
			error_log('$param: '.$param);
			return null;
		}
		return $param;
    }
    private function set_access_control_headers()
    {
		header('Access-Control-Allow-Origin: https://ipspy.net', false);
    }
    private function set_date_time_formats()
    {
    	$this->date_time_formats = $this->get_date_time_constants();
    }
    private function set_date_time_zones()
    {
    	$this->date_time_zones = $this->timezones;
    }
    private function get_date_time_constants()
    {
        return (new ReflectionClass("DateTimeInterface"))->getConstants();
    }
    private function get_api_method()
    {
		if( isset($this->request_body['api_method']) )
        {
        	$this->api_method = $this->request_body['api_method'];
        }
        else
        {
        	$this->no_api_method();
        }
    }
    private function set_character_ranges()
    {
    	$this->lowercase_characters = range('a', 'z');
    	$this->uppercase_characters = range('A', 'Z');
    	$this->numbers = range(0, 9);
    }
    private function get_client_public_ip()
    {
        if( isset($this->data['requestContext']['http']['sourceIp']) )
        {
        	$this->client_public_ip = $this->data['requestContext']['http']['sourceIp'];
        }
        elseif( isset($this->data['headers']['x-forwarded-for']) )
        {
        	$this->client_public_ip = $this->data['headers']['x-forwarded-for'];
        }
        else
        {
        	$this->client_public_ip = '0.0.0.0';
        }
    }
    private function api_method_get_public_ip()
    {
    	$return_array = ['status' => 'success', 'public_ip' => $this->client_public_ip];
    	return $this->return_json($return_array);
    }
    private function api_method_gen_rand_password($gen_pass_length = null, $use_special_chars = null, $use_upper_chars = null, $use_lower_chars = null, $use_numbers = null)
    {
    	$passed_args = func_get_args();
    	if(!empty($passed_args))
    	{
    		$internal = true;
    	}
    	else
    	{
    		$internal = false;
    	}
    	$this->set_character_ranges();
    	if(empty($gen_pass_length) && $gen_pass_length !== false)
    	{
	    	if( isset($this->request_body['gen_pass_length']) )
	        {
	        	$gen_pass_length = $this->request_body['gen_pass_length'];
	        }
	    	else
	    	{
	    		$gen_pass_length = 32;
	    	}
	    	if( $gen_pass_length < 4 )
	    	{
	    		$gen_pass_length = 4;
	    	}
	    	elseif( $gen_pass_length > 256 )
	    	{
	    		$gen_pass_length = 256;
	    	}
    	}
    	if(empty($use_special_chars) && $use_special_chars !== false)
    	{
    		if( isset($this->request_body['use_special_chars']) )
	        {
	        	$use_special_chars = $this->request_body['use_special_chars'];
	        	error_log("\$use_special_chars: {$this->request_body['use_special_chars']}");
	        }
	    	else
	    	{
	    		$use_special_chars = true;
	    	}
    	}  	
    	if(empty($use_upper_chars) && $use_upper_chars !== false)
    	{
    		if( isset($this->request_body['use_upper_chars']) )
	        {
	        	$use_upper_chars = $this->request_body['use_upper_chars'];
	        	error_log("\$use_upper_chars: {$this->request_body['use_upper_chars']}");
	        }
	    	else
	    	{
	    		$use_upper_chars = true;
	    	}
    	}
    	if(empty($use_lower_chars) && $use_lower_chars !== false)
    	{
    		if( isset($this->request_body['use_lower_chars']) )
	        {
	        	$use_lower_chars = $this->request_body['use_lower_chars'];
	        	error_log("\$use_lower_chars: {$this->request_body['use_lower_chars']}");
	        }
	    	else
	    	{
	    		$use_lower_chars = true;
	    	}
    	}
    	if(empty($use_numbers) && $use_numbers !== false)
    	{
    		if( isset($this->request_body['use_numbers']) )
	        {
	        	$use_numbers = $this->request_body['use_numbers'];
	        	error_log("\$use_numbers: {$this->request_body['use_numbers']}");
	        }
	    	else
	    	{
	    		$use_numbers = true;
	    	}
    	}
    	if(!filter_var($use_special_chars, FILTER_VALIDATE_BOOLEAN) && !filter_var($use_upper_chars, FILTER_VALIDATE_BOOLEAN) && !filter_var($use_lower_chars, FILTER_VALIDATE_BOOLEAN) && !filter_var($use_numbers, FILTER_VALIDATE_BOOLEAN))
    	{
    		return $this->no_password_characters_selected();
    	}
		$password_string = '';
		$password_characters = [];
		$character_set_map = [];
		if(filter_var($use_special_chars, FILTER_VALIDATE_BOOLEAN))
		{
			if(empty($password_characters))
			{
				$character_set_map['use_special_chars'] = ['start' => count($password_characters), 'end' => count($password_characters) + count($this->special_characters) - 1 ];
			}
			else
			{
				$character_set_map['use_special_chars'] = ['start' => count($password_characters) , 'end' => count($password_characters) + count($this->special_characters) - 1];
			}
			$password_characters = array_merge($password_characters, $this->special_characters);
		}
		if(filter_var($use_upper_chars, FILTER_VALIDATE_BOOLEAN))
		{
			if(empty($password_characters))
			{
				$character_set_map['use_upper_chars'] = ['start' => count($password_characters), 'end' => count($password_characters) + count($this->uppercase_characters) - 1 ];
			}
			else
			{
				$character_set_map['use_upper_chars'] = ['start' => count($password_characters) , 'end' => count($password_characters) + count($this->uppercase_characters) - 1];
			}
			$password_characters = array_merge($password_characters, $this->uppercase_characters);
		}
		if(filter_var($use_lower_chars, FILTER_VALIDATE_BOOLEAN))
		{
			if(empty($password_characters))
			{
				$character_set_map['use_lower_chars'] = ['start' => count($password_characters), 'end' => count($password_characters) + count($this->lowercase_characters) - 1];
			}
			else
			{
				$character_set_map['use_lower_chars'] = ['start' => count($password_characters) , 'end' => count($password_characters) + count($this->lowercase_characters) - 1];
			}
			$password_characters = array_merge($password_characters, $this->lowercase_characters);
		}
		if(filter_var($use_numbers, FILTER_VALIDATE_BOOLEAN))
		{
			if(empty($password_characters))
			{
				$character_set_map['use_numbers'] = ['start' => count($password_characters) , 'end' => count($password_characters) + count($this->numbers) - 1];
			}
			else
			{
				$character_set_map['use_numbers'] = ['start' => count($password_characters) , 'end' => count($password_characters) + count($this->numbers) - 1];
			}
			$password_characters = array_merge($password_characters, $this->numbers);
		}
		$used_numbers = [];
		for($i=0;$i<$gen_pass_length;$i++) {
			list($usec, $sec) = explode(' ', microtime());
			$seed = (float)$sec+((float)$usec*0x5f3759df) * 0x5f3759ff; // What the fuckkkkkkk???????
			mt_srand($seed);
			generate_password_character:
			$password_string_updated = false;
			if(count($used_numbers) === 4)
			{
				$used_numbers = [];
			}
			if( empty($used_numbers) )
			{
				$random_number = $this->random_number(0, 3);
				array_push($used_numbers, $random_number);
			}
			else
			{
				$random_number = $this->random_number(0, 3, $used_numbers);
				array_push($used_numbers, $random_number);
			}
			if($random_number === 0 && filter_var($use_special_chars, FILTER_VALIDATE_BOOLEAN))
			{
				$password_string .= $password_characters[mt_rand( $character_set_map['use_special_chars']['start'],  $character_set_map['use_special_chars']['end'])];
				$password_string_updated = true;
				continue;
			}
			if($random_number === 1 && filter_var($use_upper_chars, FILTER_VALIDATE_BOOLEAN))
			{
				$password_string .= $password_characters[mt_rand( $character_set_map['use_upper_chars']['start'],  $character_set_map['use_upper_chars']['end'])];
				$password_string_updated = true;
				continue;
			}
			if($random_number === 2 && filter_var($use_lower_chars, FILTER_VALIDATE_BOOLEAN))
			{
				$password_string .= $password_characters[mt_rand( $character_set_map['use_lower_chars']['start'],  $character_set_map['use_lower_chars']['end'])];
				$password_string_updated = true;
				continue;
			}
			if($random_number === 3 && filter_var($use_numbers, FILTER_VALIDATE_BOOLEAN))
			{
				$password_string .= $password_characters[mt_rand( $character_set_map['use_numbers']['start'],  $character_set_map['use_numbers']['end'])];
				$password_string_updated = true;
				continue;
			}
			if(!$password_string_updated)
			{
				goto generate_password_character;
			}
		}
		$return_array = ['status' => 'success', 'password' => $password_string];
		if($internal)
		{
			return $return_array;
		}
		return $this->return_json($return_array);
    }
    private function is_prime($n){for($i=$n**.5|1;$i&&$n%$i--;);return!$i&&$n>1;} // Seriously what the fuckkkkk??
    private function random_number(int $from, int $to, array $excluded = [])
	{
	    $func = function_exists('random_int') ? 'random_int' : 'mt_rand';
	    do {
	        $number = $func($from, $to);
	    } while (in_array($number, $excluded, true));
	    return $number;
	}
    private function api_method_get_whois_records(string $whois_lookup_host = null)
    {
		if( !empty($whois_lookup_host) )
		{
			$internal_lookup = true;
		}
		if( empty($whois_lookup_host) )
		{
			$internal_lookup = false;
			if( isset($this->request_body['whois_lookup_host']) )
	        {
	        	$whois_lookup_host = $this->request_body['whois_lookup_host'];
	        }
			else
			{
				$this->no_whois_lookup_host();
			}
		}
		$domain_parts = explode('.', $whois_lookup_host);
		$domain_ending = end($domain_parts);
		error_log("\$domain_ending: {$domain_ending}");
		if( isset($this->whois_servers[$domain_ending]) )
		{
			$whois_host = $this->whois_servers[$domain_ending];
			error_log("\$whois_host: {$whois_host}");
		}
		if( isset($whois_host) )
		{
			$whois = shell_exec("whois -h {$whois_host} {$whois_lookup_host}");
		}
		else
		{
			$whois = shell_exec("whois {$whois_lookup_host}");
		}
		if( !empty($whois) )
		{
			$whois = preg_replace('/(\>\>\>)/', '', $whois);
			$whois = preg_replace('/(\<\<\<)/', "\nDisclaimer: ", $whois);
			// $whois = preg_replace('/(database:)/', 'database::', $whois);
			$whois = preg_replace('/(to:)/', 'to::', $whois);
			$whois = preg_replace('/(use:)/', 'use::', $whois);
			$result = explode("\n",$whois);
			$return_array = ['status' => 'success'];
			$last_key = '';
			foreach ($result as $index => $line){
			    if (substr($line,0,1) == '%' || substr($line,0,1) == '#')
			    { 
			    	continue; 
			    }
				$ps = preg_split('/(?<=\w)(\:)(?=\s)/', $line);
				if( isset($ps[0]) && empty($ps[0]) )
				{
					continue;
				}
			    if( isset($ps[0]) && isset($ps[1]) )
			    {
			    	$return_array[trim($ps[0])] = trim($ps[1]);
			    	$last_key = trim($ps[0]);
			    }
			    elseif( isset($ps[0]) && !empty($ps[0]) && empty($last_key) )
			    {
			    	$return_array[trim($ps[0])] = '';
			    	$last_key = trim($ps[0]);
			    }
			    elseif( isset($ps[0]) && !empty($ps[0]) && !empty($last_key) )
			    {
			    	if( preg_match('/(\:)/', $ps[0]) )
			    	{
			    		if( preg_match('/(\:\:)/', $ps[0]) )
			    		{
			    			$return_array[$last_key] .= ' '.trim($ps[0]);
			    		}
			    		elseif( preg_match('/(https?\:\/\/)/', $ps[0]) )
			    		{
			    			$return_array[$last_key] .= ' '.trim($ps[0]);
			    		}
			    		else
			    		{
			    			$return_array[trim($ps[0])] = '';
			    			$last_key = trim($ps[0]);
			    		}
			    	}
			    	else
			    	{
			    		$return_array[$last_key] .= ' '.trim($ps[0]);
			    	}
			    }
			}
			if(!$internal_lookup)
			{
				return $this->return_json($return_array);
			}
			if($internal_lookup)
			{
				return $return_array;
			}
		}
		else
		{
			return $this->whois_lookup_failed();
		}
    }
    private function api_method_set_uuid_cookie()
    {
    	$domain = ($_SERVER['HTTP_HOST'] != 'localhost') ? $_SERVER['HTTP_HOST'] : false;
    	$cookie_options = array (
                'expires' => time() + (60*60*24*365*256),
                'path' => '/',
                'domain' => $domain, // leading dot for compatibility or use subdomain
                'secure' => true,     // or false
                );
    	$uuid = $this->gen_uuid();
    	$private_key = $this->api_method_gen_rand_password(256, false, true, true, true);
    	$private_key = $private_key['password'];
		$return_array = ['status' => 'success', 'uuid' => $uuid, 'private_key' => $private_key, 'cookie_options' => $cookie_options];
		return $this->return_json($return_array);
    }
    private function api_method_get_uuid_cookie()
    {
    	if (isset($_COOKIE['uuid'])) {
		    $return_array = ['status' => 'success', 'uuid' => $_COOKIE['uuid']];
		}
		return $this->return_json($return_array);
    }
    private function api_method_get_geo_location()
    {
    	if( isset($this->request_body['geo_location_ip']) )
        {
        	$geo_location_ip = $this->request_body['geo_location_ip'];
        }
    	else
    	{
    		$geo_location_ip = $this->client_public_ip;
    	}
		$url = "https://tools.keycdn.com/geo.json?host={$geo_location_ip}";
		$whois = $this->api_method_get_whois_records($geo_location_ip);
		if(isset($whois['OrgName']))
		{
			$org_name = $whois['OrgName'];
		}
		else
		{
			$org_name = 'UNKNOWN';
		}
		try {
		    $ch = curl_init($url);
		    if (FALSE === $ch)
		    {
		    	throw new Exception('failed to initialize');
		    }
	        curl_setopt($ch, CURLOPT_CUSTOMREQUEST, "GET");
	        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
	        curl_setopt($ch, CURLOPT_FOLLOWLOCATION, 1);
	        curl_setopt($ch, CURLOPT_HTTPHEADER, ['Content-Type: application/json', 'User-Agent: keycdn-tools:https://tools.keycdn.com']); // Updated, Thrusday April 7th 2022
	        curl_setopt($ch, CURLOPT_TIMEOUT, 5);
	        curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 5);
	        $curl_return = json_decode(curl_exec($ch), true);
	        $curl_return['data']['geo']['org_name'] = $org_name;
	        $return_array = ['status' => 'success', 'ip_geo_location' => $curl_return];
			return $this->return_json($return_array);
		    if ($curl_return === FALSE)
		    {
		    	throw new Exception(curl_error($ch), curl_errno($ch));
		    }
		} catch(Exception $e) {
		
		    trigger_error(sprintf('Curl failed with error #%d: %s',$e->getCode(), $e->getMessage()),E_USER_ERROR);
		}
    }
    private function api_method_get_reverse_dns()
    {
    	$return_array = ['status' => 'success', 'reverse_dns' => gethostbyaddr($this->client_public_ip)];
		return $this->return_json($return_array);
    }
    private function api_method_get_date_times()
    {
    	$this->set_date_time_formats();
    	$this->set_date_time_zones();
    	if( isset($this->request_body['datetime_string']) && !empty($this->request_body['datetime_string']) )
        {
        	$datetime_string = $this->filter_request_param_string($this->request_body['datetime_string']);
    		if(empty($datetime_string))
    		{
    			$datetime_string = date("Y-m-d H:i:s");
    		}
        }
    	else
    	{
    		$datetime_string = date("Y-m-d H:i:s");
    	}
    	if( isset($this->request_body['datetime_format']) && !empty($this->request_body['datetime_format']) )
        {
        	$datetime_format = $this->filter_request_param_string($this->request_body['datetime_format']);
        }
    	else
    	{
    		$datetime_format = null;
    	}
    	if( isset($this->request_body['datetime_custom_format']) )
        {
        	$datetime_custom_format = $this->filter_request_param_string($this->request_body['datetime_custom_format']);
    		
    		if(!empty($datetime_custom_format))
    		{
    			$datetime_format = $datetime_custom_format;
    		}
        }
    	else
    	{
    		$datetime_custom_format = null;
    	}
    	if( isset($this->request_body['datetime_timezone']) && !empty($this->request_body['datetime_timezone']) )
        {
        	$datetime_timezone = $this->filter_request_param_string($this->request_body['datetime_timezone']);
    		if(isset($this::$timezone_to_php[$datetime_timezone]))
    		{
    			$datetime_timezone = $this::$timezone_to_php[$datetime_timezone];
    			date_default_timezone_set($datetime_timezone);
    		}
        }
    	$time = strtotime($datetime_string);
    	$date_times = [];
    	if(!empty($datetime_custom_format) )
    	{
    		$date_time = date($datetime_format, $time);
    		$date_times[$datetime_format] = $date_time;
    	}
    	foreach($this->date_time_formats as $date_time_format)
    	{
    		$date_time = date($date_time_format, $time);
    		$date_times[$date_time_format] = $date_time;
    	}
    	if(!empty($datetime_format))
    	{
    		foreach($this->date_time_zones as $date_time_zone)
	    	{
	    		$DateTime = new DateTime();
				$DateTime->setTimezone(new DateTimeZone($date_time_zone));
				$DateTime->setTimestamp($time);
				$date_times['filter'][$datetime_format][] = $DateTime->format($datetime_format);
				$date_times['filter'][$datetime_format] = array_unique($date_times['filter'][$datetime_format]);
				sort($date_times['filter'][$datetime_format]);
	    	}
    	}
    	if(!empty($datetime_timezone))
    	{
    		foreach($this->date_time_formats as $date_time_format)
	    	{
	    		$DateTime = new DateTime();
				$DateTime->setTimezone(new DateTimeZone($datetime_timezone));
				$DateTime->setTimestamp($time);
				$date_times['filter'][$datetime_timezone][] = $DateTime->format($date_time_format);
				$date_times['filter'][$datetime_timezone] = array_unique($date_times['filter'][$datetime_timezone]);
				sort($date_times['filter'][$datetime_timezone]);
	    	}
    	}
    	foreach($this->date_time_formats as $date_time_format)
    	{
	    	foreach($this->date_time_zones as $date_time_zone)
	    	{
	    		$DateTime = new DateTime();
				$DateTime->setTimezone(new DateTimeZone($date_time_zone));
				$DateTime->setTimestamp($time);
				$date_times['timezones'][$date_time_zone][$date_time_format] = $DateTime->format($date_time_format);
				$date_times['unique'][$date_time_format][] = $DateTime->format($date_time_format);
				$date_times['timezones'][$date_time_zone] = array_unique($date_times['timezones'][$date_time_zone]);
				$date_times['unique'][$date_time_format] = array_unique($date_times['unique'][$date_time_format]);
				sort($date_times['unique'][$date_time_format]);
	    	}
    	}
    	$date_times = array_map("unserialize", array_unique(array_map("serialize", $date_times)));
    	$return_array = ['status' => 'success', 'date_times' => $date_times];
    	return $this->return_json($return_array);
    }
    private function api_method_get_dns_records()
    {
    	if( isset($this->request_body['dns_lookup_type']) )
        {
        	$lookup_type = $this->request_body['dns_lookup_type'];
        }
    	else
    	{
    		$lookup_type = null;
    	}
    	if( isset($this->request_body['dns_lookup_host']) && !empty($this->request_body['dns_lookup_host']) )
        {
    		$lookup_host = $this->request_body['dns_lookup_host'];
    	}
    	else
    	{
    		$this->no_dns_lookup_host();
    	}
    	$authoritative_name_servers = ['1.1.1.1', '8.8.8.8'];
    	if( isset($lookup_host) && !empty($lookup_host) )
    	{
    		switch ($lookup_type) {
			    case 'DNS_ANY':
			    	$dns_lookup_results = dns_get_record($lookup_host, DNS_ANY, $authoritative_name_servers);
			    	break;
			    case 'DNS_A':
			    	$dns_lookup_results = dns_get_record($lookup_host, DNS_A, $authoritative_name_servers);
			    	break;
			    case 'DNS_AAAA':
			    	$dns_lookup_results = dns_get_record($lookup_host, DNS_AAAA, $authoritative_name_servers);
			    	break;
			    case 'DNS_MX':
			    	$dns_lookup_results = dns_get_record($lookup_host, DNS_MX, $authoritative_name_servers);
			    	break;
			    case 'DNS_NS':
			    	$dns_lookup_results = dns_get_record($lookup_host, DNS_NS, $authoritative_name_servers);
			    	break;
			    case 'DNS_CNAME':
			    	$dns_lookup_results = dns_get_record($lookup_host, DNS_CNAME, $authoritative_name_servers);
			    	break;
			    case 'DNS_TXT':
			    	$dns_lookup_results = dns_get_record($lookup_host, DNS_TXT, $authoritative_name_servers);
			    	break;
			    case 'DNS_ALL':
			    	$dns_lookup_results = dns_get_record($lookup_host, DNS_ALL, $authoritative_name_servers);
			    	break;
			    default:
			    	$dns_lookup_results = dns_get_record($lookup_host, DNS_ALL, $authoritative_name_servers);
			    	break;    	
			}	
    	}
		if( isset($dns_lookup_results) && !empty($dns_lookup_results) )
		{
			$return_array = ['status' => 'success', 'dns_records' => $dns_lookup_results];
    		return $this->return_json($return_array);
		}
		else
		{
			return $this->no_dns_records($lookup_host, $lookup_type);
		}
    }
    private function no_date_string()
    {
    	$return_array = ['status' => 'error', 'message' => 'No `date_string` provided. Please include an `date_string` and try your request again.'];
    	return $this->return_json($return_array);
    }
    private function no_dns_records(string $lookup_host, string $lookup_type)
    {
    	$return_array = ['status' => 'error', 'message' => "No {$lookup_type} records exist for host `{$lookup_host}`"];
    	return $this->return_json($return_array);
    }
    private function no_password_characters_selected()
    {
    	$return_array = ['status' => 'error', 'message' => "You must select at least one character type to include in your passsword generation."];
    	return $this->return_json($return_array);
    }
    private function no_whois_lookup_host()
    {
    	$return_array = ['status' => 'error', 'message' => 'No `whois_lookup_host` provided. Please include an `whois_lookup_host` and try your request again.'];
    	return $this->return_json($return_array);
    }
    private function whois_lookup_failed()
    {
    	$return_array = ['status' => 'error', 'message' => 'Whois lookup failed for an unknown reason, please check the `whois_lookup_host` and try again.'];
    	return $this->return_json($return_array);
    }
    private function no_dns_lookup_host()
    {
    	$return_array = ['status' => 'error', 'message' => 'No `dns_lookup_host` provided. Please include an `dns_lookup_host` and try your request again.'];
    	return $this->return_json($return_array);
    }
    private function no_api_method()
    {
    	$return_array = ['status' => 'error', 'message' => 'No `api_method` provided. Please include an `api_method` and try your request again.'];
    	return $this->return_json($return_array);
    }
    private function return_json(array $return_array)
    {
		return json_encode($return_array);
    }
    private function save_file_level_array(string $var, array $var_array)
    {
    	$uuid = $this->gen_uuid();
    	$file_name = __DIR__ . $this::$file_level_array_directory . $var;
    	if(file_exists($file_name))
    	{
    		rename($file_name, $file_name.'-'.$uuid);
    		file_put_contents($file_name, json_encode($var_array));
    		return true;
    	}
    	else
    	{
    		file_put_contents($file_name, json_encode($var_array));
    		return true;
    	}
    	return false;
    }
    private function read_file_level_array(string $var)
    {
    	$file_name = __DIR__ . $this::$file_level_array_directory . $var;
    	if(file_exists($file_name))
    	{
    		return json_decode(file_get_contents($file_name), true);
    		 
    	}
    	return false;
    }
    private function update_file_level_array(string $var, array $var_array)
    {
    	$uuid = $this->gen_uuid();
    	$file_name = __DIR__ . $this::$file_level_array_directory . $var;
    	if(file_exists($file_name))
    	{
    		$data1 = $this->read_file_level_array($var);
    		$data2 = $var_array;
    		if($data1 === $data2)
    		{
    			return false;
    		}
    		if($data1 !== $data2)
    		{
				$this->save_file_level_array($var, $var_array);
    		}
    	}
		return false;
    }
    private function gen_uuid() {
	    return sprintf( '%04x%04x-%04x-%04x-%04x-%04x%04x%04x',
	        mt_rand( 0, 0xffff ), mt_rand( 0, 0xffff ),
	        mt_rand( 0, 0xffff ),
	        mt_rand( 0, 0x0fff ) | 0x4000,
	        mt_rand( 0, 0x3fff ) | 0x8000,
	        mt_rand( 0, 0xffff ), mt_rand( 0, 0xffff ), mt_rand( 0, 0xffff )
	    );
	}
    private function route_api_method()
    {
    	switch ($this->api_method) {
		    case 'get_public_ip':
		    	return $this->api_method_get_public_ip();
		    	break;
	    	case 'get_dns_records':
	    		return $this->api_method_get_dns_records();
	    		break;
	    	case 'get_whois_records':
	    		return $this->api_method_get_whois_records();
	    		break;
	    	case 'get_reverse_dns':
	    		return $this->api_method_get_reverse_dns();
	    		break;
	    	case 'get_geo_location':
	    		return $this->api_method_get_geo_location();
	    		break;
	    	case 'gen_rand_password':
	    		return $this->api_method_gen_rand_password();
	    		break;
	    	case 'get_date_times':
	    		return $this->api_method_get_date_times();
	    		break;
	    	case 'set_uuid_cookie':
	    		return $this->api_method_set_uuid_cookie();
	    		break;
	    	case 'get_uuid_cookie':
	    		return $this->api_method_get_uuid_cookie();
	    		break;
		}
    } 
}
function index($data)
{
	$ipspy_api = new ipspy_api();
	return $ipspy_api->init($data);
}
#NoFucqsGiven
?>
