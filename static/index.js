(function() {
$(document).ready(function() {
	var apiID = null;
	var apiKey = null;
	var ip = null;
	var hostname = null;

	// build TZ timezones selections
	var tzElement = $('#tz');
	TIMEZONES.forEach(function(timezone) {
		var el = document.createElement('option');
		el.setAttribute('value', timezone);
		el.innerText = timezone;
		if (timezone === 'Etc/UTC') {
			el.setAttribute('selected', '');
		}
		tzElement.append(el);
	});

	function showError(msg) {
		if(msg) {
			$('#errorbar').text(msg);
			$('#errorbar').css('display', '');
		} else {
			$('#errorbar').css('display', 'none');
		}
	}

	function showStep(id) {
		showError();
		$('.stepdiv').css('display', 'none');
		$('#' + id).css('display', '');

		if(id === 'step3') {
			updatePrice();
		}
	}

	function getAutoHostname() {
		return 'teslamate' + (1000000 + Math.floor(Math.random() * 8999999)) + '.lndyn.com';
	}

	$('#step1_form').submit(function(e) {
		e.preventDefault();
		apiID = $('#api_id').val();
		apiKey = $('#api_key').val();
		$('#api_id').val('');
		$('#api_key').val('');

		if(apiID.length < 5 || apiKey.length < 5) {
			showError('Invalid API ID or API key.');
			return;
		}

		showStep('loading');
		var params = {
			'api_id': apiID,
			'api_key': apiKey,
		};
		$.post('/getip', params, function(data) {
			if(data.error) {
				showStep('step1');
				showError('Error: ' + data.error + '.');
				return;
			}

			ip = data.ip;
			$('#step2_ip').text(ip);
			var autohostname = getAutoHostname();
			$('#step2_autohostname').text(autohostname);
			showStep('step2');
		}, 'json');
	});

	$('#step2_form').submit(function(e) {
		e.preventDefault();
		if($('.hostname_type:checked').data('type') === 'autohostname') {
			hostname = $('#step2_autohostname').text();
		} else {
			hostname = $('#hostname').val();
		}
		hostname = hostname.trim();
		if(hostname.length == 0) {
			showError('Hostname cannot be empty!');
			return;
		} else if(hostname.indexOf('http://') !== -1 || hostname.indexOf('https://') !== -1) {
			showError('Please enter just the hostname (e.g. "example.com", without http:// or URL path).');
			return;
		} else if(hostname.indexOf(':') !== -1) {
			showError('Please enter just the hostname (e.g., "example.com" or "teslamate.example.com").')
			return;
		} else if(/^[0-9]*\.[0-9]*\.[0-9]*\.[0-9]*$/.test(hostname)) {
			showError('Please enter a hostname like "example.com" or "teslamate.example.com", not an IP address.');
			return;
		}

		showStep('step3');
	});

	$('#step3_form').submit(function(e) {
		e.preventDefault();

		var nginxPassword = $('#nginxPassword').val();
		var nginxPassword2 = $('#nginxPassword2').val();

		if (!nginxPassword || nginxPassword !== nginxPassword2) {
			showError('Please make sure your password and the confirmation field match.');
			return;
		}

		var tz = $('#tz').val();

		if (!tz || TIMEZONES.indexOf(tz) === -1) {
			showError('Please use a valid TZ timezone.');
			return;
		}

		showStep('loading2');

		var params = {
			'api_id': apiID,
			'api_key': apiKey,
			'ip': ip,
			'hostname': hostname,
			'nginxPassword': nginxPassword,
			'tz': tz,
			'sshkey': $('#sshkey').val(),
			'email': $('#email').val(),
			'repository': $('#repository').val(),
			'branch': $('#branch').val(),
			'plan': $('#plan').val(),
		};
		$.post('/launch', params, function(data) {
			if(data.error) {
				if (data.error.match(/^specified name \[[^\]]+\] already taken$/)) {
					$('#step2_autohostname').text(getAutoHostname());
					showStep('step2');
					showError('Error: ' + data.error + '.');
					return;
				}
				showStep('step3');
				showError('Error: ' + data.error + '.');
				return;
			}

			$('#step4_hostname').attr('href', 'https://' + hostname);
			$('#step4_hostname').text('https://' + hostname);
			$('#urls_content').html('Web App: https://' + hostname + '<br>Dashboards: https://' + hostname + '/grafana');
			showStep('step4');

			// Wait for server to be up
			var timeleft = { minutes: 10, seconds: 0 };
			$('#timer').text(timeleft.minutes + ' minutes ' + timeleft.seconds + ' seconds left');
			var INTERVAL_CODE = setInterval(function() {
				if (timeleft.seconds <= 0) {
					timeleft.minutes--;
					timeleft.seconds = 59;
				} else {
					timeleft.seconds--;
				}
				if (timeleft.minutes < 0) {
					clearInterval(INTERVAL_CODE);
					return;
				}
				$('#timer').text(timeleft.minutes + ' minutes ' + timeleft.seconds + ' seconds left');
			}, 1 * 1000);

		}, 'json');
	});

	function updatePrice() {
		var planOption = $('#plan').find(":selected");
		var price = parseFloat(planOption.data('price'));
		$('#price').val('$' + price.toFixed(2));
	}

	$('#plan').on('change', function(e) {
		updatePrice();
	});

	$('.hostname_type').on('change', function(e) {
		if($('.hostname_type:checked').data('type') === 'autohostname') {
			$('#hostname').prop('disabled', true);
		} else {
			$('#hostname').prop('disabled', false);
		}
	});
});

var TIMEZONES = ['Africa/Abidjan','Africa/Accra','Africa/Addis_Ababa','Africa/Algiers','Africa/Asmara','Africa/Asmera','Africa/Bamako','Africa/Bangui','Africa/Banjul','Africa/Bissau','Africa/Blantyre','Africa/Brazzaville','Africa/Bujumbura','Africa/Cairo','Africa/Casablanca','Africa/Ceuta','Africa/Conakry','Africa/Dakar','Africa/Dar_es_Salaam','Africa/Djibouti','Africa/Douala','Africa/El_Aaiun','Africa/Freetown','Africa/Gaborone','Africa/Harare','Africa/Johannesburg','Africa/Juba','Africa/Kampala','Africa/Khartoum','Africa/Kigali','Africa/Kinshasa','Africa/Lagos','Africa/Libreville','Africa/Lome','Africa/Luanda','Africa/Lubumbashi','Africa/Lusaka','Africa/Malabo','Africa/Maputo','Africa/Maseru','Africa/Mbabane','Africa/Mogadishu','Africa/Monrovia','Africa/Nairobi','Africa/Ndjamena','Africa/Niamey','Africa/Nouakchott','Africa/Ouagadougou','Africa/Porto-Novo','Africa/Sao_Tome','Africa/Timbuktu','Africa/Tripoli','Africa/Tunis','Africa/Windhoek','America/Adak','America/Anchorage','America/Anguilla','America/Antigua','America/Araguaina','America/Argentina/Buenos_Aires','America/Argentina/Catamarca','America/Argentina/ComodRivadavia','America/Argentina/Cordoba','America/Argentina/Jujuy','America/Argentina/La_Rioja','America/Argentina/Mendoza','America/Argentina/Rio_Gallegos','America/Argentina/Salta','America/Argentina/San_Juan','America/Argentina/San_Luis','America/Argentina/Tucuman','America/Argentina/Ushuaia','America/Aruba','America/Asuncion','America/Atikokan','America/Atka','America/Bahia','America/Bahia_Banderas','America/Barbados','America/Belem','America/Belize','America/Blanc-Sablon','America/Boa_Vista','America/Bogota','America/Boise','America/Buenos_Aires','America/Cambridge_Bay','America/Campo_Grande','America/Cancun','America/Caracas','America/Catamarca','America/Cayenne','America/Cayman','America/Chicago','America/Chihuahua','America/Coral_Harbour','America/Cordoba','America/Costa_Rica','America/Creston','America/Cuiaba','America/Curacao','America/Danmarkshavn','America/Dawson','America/Dawson_Creek','America/Denver','America/Detroit','America/Dominica','America/Edmonton','America/Eirunepe','America/El_Salvador','America/Ensenada','America/Fort_Nelson','America/Fort_Wayne','America/Fortaleza','America/Glace_Bay','America/Godthab','America/Goose_Bay','America/Grand_Turk','America/Grenada','America/Guadeloupe','America/Guatemala','America/Guayaquil','America/Guyana','America/Halifax','America/Havana','America/Hermosillo','America/Indiana/Indianapolis','America/Indiana/Knox','America/Indiana/Marengo','America/Indiana/Petersburg','America/Indiana/Tell_City','America/Indiana/Vevay','America/Indiana/Vincennes','America/Indiana/Winamac','America/Indianapolis','America/Inuvik','America/Iqaluit','America/Jamaica','America/Jujuy','America/Juneau','America/Kentucky/Louisville','America/Kentucky/Monticello','America/Knox_IN','America/Kralendijk','America/La_Paz','America/Lima','America/Los_Angeles','America/Louisville','America/Lower_Princes','America/Maceio','America/Managua','America/Manaus','America/Marigot','America/Martinique','America/Matamoros','America/Mazatlan','America/Mendoza','America/Menominee','America/Merida','America/Metlakatla','America/Mexico_City','America/Miquelon','America/Moncton','America/Monterrey','America/Montevideo','America/Montreal','America/Montserrat','America/Nassau','America/New_York','America/Nipigon','America/Nome','America/Noronha','America/North_Dakota/Beulah','America/North_Dakota/Center','America/North_Dakota/New_Salem','America/Nuuk','America/Ojinaga','America/Panama','America/Pangnirtung','America/Paramaribo','America/Phoenix','America/Port-au-Prince','America/Port_of_Spain','America/Porto_Acre','America/Porto_Velho','America/Puerto_Rico','America/Punta_Arenas','America/Rainy_River','America/Rankin_Inlet','America/Recife','America/Regina','America/Resolute','America/Rio_Branco','America/Rosario','America/Santa_Isabel','America/Santarem','America/Santiago','America/Santo_Domingo','America/Sao_Paulo','America/Scoresbysund','America/Shiprock','America/Sitka','America/St_Barthelemy','America/St_Johns','America/St_Kitts','America/St_Lucia','America/St_Thomas','America/St_Vincent','America/Swift_Current','America/Tegucigalpa','America/Thule','America/Thunder_Bay','America/Tijuana','America/Toronto','America/Tortola','America/Vancouver','America/Virgin','America/Whitehorse','America/Winnipeg','America/Yakutat','America/Yellowknife','Antarctica/Casey','Antarctica/Davis','Antarctica/DumontDUrville','Antarctica/Macquarie','Antarctica/Mawson','Antarctica/McMurdo','Antarctica/Palmer','Antarctica/Rothera','Antarctica/South_Pole','Antarctica/Syowa','Antarctica/Troll','Antarctica/Vostok','Arctic/Longyearbyen','Asia/Aden','Asia/Almaty','Asia/Amman','Asia/Anadyr','Asia/Aqtau','Asia/Aqtobe','Asia/Ashgabat','Asia/Ashkhabad','Asia/Atyrau','Asia/Baghdad','Asia/Bahrain','Asia/Baku','Asia/Bangkok','Asia/Barnaul','Asia/Beirut','Asia/Bishkek','Asia/Brunei','Asia/Calcutta','Asia/Chita','Asia/Choibalsan','Asia/Chongqing','Asia/Chungking','Asia/Colombo','Asia/Dacca','Asia/Damascus','Asia/Dhaka','Asia/Dili','Asia/Dubai','Asia/Dushanbe','Asia/Famagusta','Asia/Gaza','Asia/Harbin','Asia/Hebron','Asia/Ho_Chi_Minh','Asia/Hong_Kong','Asia/Hovd','Asia/Irkutsk','Asia/Istanbul','Asia/Jakarta','Asia/Jayapura','Asia/Jerusalem','Asia/Kabul','Asia/Kamchatka','Asia/Karachi','Asia/Kashgar','Asia/Kathmandu','Asia/Katmandu','Asia/Khandyga','Asia/Kolkata','Asia/Krasnoyarsk','Asia/Kuala_Lumpur','Asia/Kuching','Asia/Kuwait','Asia/Macao','Asia/Macau','Asia/Magadan','Asia/Makassar','Asia/Manila','Asia/Muscat','Asia/Nicosia','Asia/Novokuznetsk','Asia/Novosibirsk','Asia/Omsk','Asia/Oral','Asia/Phnom_Penh','Asia/Pontianak','Asia/Pyongyang','Asia/Qatar','Asia/Qostanay','Asia/Qyzylorda','Asia/Rangoon','Asia/Riyadh','Asia/Saigon','Asia/Sakhalin','Asia/Samarkand','Asia/Seoul','Asia/Shanghai','Asia/Singapore','Asia/Srednekolymsk','Asia/Taipei','Asia/Tashkent','Asia/Tbilisi','Asia/Tehran','Asia/Tel_Aviv','Asia/Thimbu','Asia/Thimphu','Asia/Tokyo','Asia/Tomsk','Asia/Ujung_Pandang','Asia/Ulaanbaatar','Asia/Ulan_Bator','Asia/Urumqi','Asia/Ust-Nera','Asia/Vientiane','Asia/Vladivostok','Asia/Yakutsk','Asia/Yangon','Asia/Yekaterinburg','Asia/Yerevan','Atlantic/Azores','Atlantic/Bermuda','Atlantic/Canary','Atlantic/Cape_Verde','Atlantic/Faeroe','Atlantic/Faroe','Atlantic/Jan_Mayen','Atlantic/Madeira','Atlantic/Reykjavik','Atlantic/South_Georgia','Atlantic/St_Helena','Atlantic/Stanley','Australia/ACT','Australia/Adelaide','Australia/Brisbane','Australia/Broken_Hill','Australia/Canberra','Australia/Currie','Australia/Darwin','Australia/Eucla','Australia/Hobart','Australia/LHI','Australia/Lindeman','Australia/Lord_Howe','Australia/Melbourne','Australia/North','Australia/NSW','Australia/Perth','Australia/Queensland','Australia/South','Australia/Sydney','Australia/Tasmania','Australia/Victoria','Australia/West','Australia/Yancowinna','Brazil/Acre','Brazil/DeNoronha','Brazil/East','Brazil/West','Canada/Atlantic','Canada/Central','Canada/Eastern','Canada/Mountain','Canada/Newfoundland','Canada/Pacific','Canada/Saskatchewan','Canada/Yukon','CET','Chile/Continental','Chile/EasterIsland','CST6CDT','Cuba','EET','Egypt','Eire','EST','EST5EDT','Etc/GMT','Etc/GMT+0','Etc/GMT+1','Etc/GMT+10','Etc/GMT+11','Etc/GMT+12','Etc/GMT+2','Etc/GMT+3','Etc/GMT+4','Etc/GMT+5','Etc/GMT+6','Etc/GMT+7','Etc/GMT+8','Etc/GMT+9','Etc/GMT-0','Etc/GMT-1','Etc/GMT-10','Etc/GMT-11','Etc/GMT-12','Etc/GMT-13','Etc/GMT-14','Etc/GMT-2','Etc/GMT-3','Etc/GMT-4','Etc/GMT-5','Etc/GMT-6','Etc/GMT-7','Etc/GMT-8','Etc/GMT-9','Etc/GMT0','Etc/Greenwich','Etc/UCT','Etc/Universal','Etc/UTC','Etc/Zulu','Europe/Amsterdam','Europe/Andorra','Europe/Astrakhan','Europe/Athens','Europe/Belfast','Europe/Belgrade','Europe/Berlin','Europe/Bratislava','Europe/Brussels','Europe/Bucharest','Europe/Budapest','Europe/Busingen','Europe/Chisinau','Europe/Copenhagen','Europe/Dublin','Europe/Gibraltar','Europe/Guernsey','Europe/Helsinki','Europe/Isle_of_Man','Europe/Istanbul','Europe/Jersey','Europe/Kaliningrad','Europe/Kiev','Europe/Kirov','Europe/Lisbon','Europe/Ljubljana','Europe/London','Europe/Luxembourg','Europe/Madrid','Europe/Malta','Europe/Mariehamn','Europe/Minsk','Europe/Monaco','Europe/Moscow','Europe/Nicosia','Europe/Oslo','Europe/Paris','Europe/Podgorica','Europe/Prague','Europe/Riga','Europe/Rome','Europe/Samara','Europe/San_Marino','Europe/Sarajevo','Europe/Saratov','Europe/Simferopol','Europe/Skopje','Europe/Sofia','Europe/Stockholm','Europe/Tallinn','Europe/Tirane','Europe/Tiraspol','Europe/Ulyanovsk','Europe/Uzhgorod','Europe/Vaduz','Europe/Vatican','Europe/Vienna','Europe/Vilnius','Europe/Volgograd','Europe/Warsaw','Europe/Zagreb','Europe/Zaporozhye','Europe/Zurich','Factory','GB','GB-Eire','GMT','GMT+0','GMT-0','GMT0','Greenwich','Hongkong','HST','Iceland','Indian/Antananarivo','Indian/Chagos','Indian/Christmas','Indian/Cocos','Indian/Comoro','Indian/Kerguelen','Indian/Mahe','Indian/Maldives','Indian/Mauritius','Indian/Mayotte','Indian/Reunion','Iran','Israel','Jamaica','Japan','Kwajalein','Libya','MET','Mexico/BajaNorte','Mexico/BajaSur','Mexico/General','MST','MST7MDT','Navajo','NZ','NZ-CHAT','Pacific/Apia','Pacific/Auckland','Pacific/Bougainville','Pacific/Chatham','Pacific/Chuuk','Pacific/Easter','Pacific/Efate','Pacific/Enderbury','Pacific/Fakaofo','Pacific/Fiji','Pacific/Funafuti','Pacific/Galapagos','Pacific/Gambier','Pacific/Guadalcanal','Pacific/Guam','Pacific/Honolulu','Pacific/Johnston','Pacific/Kiritimati','Pacific/Kosrae','Pacific/Kwajalein','Pacific/Majuro','Pacific/Marquesas','Pacific/Midway','Pacific/Nauru','Pacific/Niue','Pacific/Norfolk','Pacific/Noumea','Pacific/Pago_Pago','Pacific/Palau','Pacific/Pitcairn','Pacific/Pohnpei','Pacific/Ponape','Pacific/Port_Moresby','Pacific/Rarotonga','Pacific/Saipan','Pacific/Samoa','Pacific/Tahiti','Pacific/Tarawa','Pacific/Tongatapu','Pacific/Truk','Pacific/Wake','Pacific/Wallis','Pacific/Yap','Poland','Portugal','PRC','PST8PDT','ROC','ROK','Singapore','Turkey','UCT','Universal','US/Alaska','US/Aleutian','US/Arizona','US/Central','US/East-Indiana','US/Eastern','US/Hawaii','US/Indiana-Starke','US/Michigan','US/Mountain','US/Pacific','US/Samoa','UTC','W-SU','WET','Zulu'];
})();
