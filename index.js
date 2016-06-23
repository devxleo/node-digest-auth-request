var http = require('http');
var https = require('https');
var crypto = require('crypto');

var DEBUG_MODE = 'debug';
var RELEASE_MODE = 'release';
var MODE = process.env['MODE'] === DEBUG_MODE ? DEBUG_MODE : RELEASE_MODE;

function isDebug() {
	return MODE === DEBUG_MODE;
}

var delimiter = '-------------------------------';
var ERROR_STATUS_CODE = 'Server response status code other than 401!';
var ERROR_WRONG_WWW_AUTHENTICATE_HEADER = 'Invalid www-authenticate header!';

/**
 * @param {object} option
 * @param {string} option.protocol - http or https, defaults to http
 * @param {string} option.hostname
 * @param {string} option.path - defaults to '/'
 * @param {string} option.method
 * @param {json} option.data - request data, only support content-type of application/json
 * @param {string} option.username
 * @param {string} option.password
 */
function request(option, callback) {
	var r = option.protocol === 'https' ? https.request : http.request;
	
	var hostname = option.hostname || 'localhost';
	var path = option.path || '/';
	var method = option.method || 'GET';
	var requestData = option.data ? JSON.stringify(option.data) : null;
	
	var reqOneOption = {
		hostname: option.hostname,
		path: option.path,
		method: option.method
	};
	if (requestData) {
		reqOneOption.headers = {
			'Content-Type': 'application/json',
			'Content-Length': requestData.length
		};
	}
	
	var reqOne = r(reqOneOption, function (res) {
		var statusCode = res.statusCode;
		if (statusCode !== 401) {
			log(`status code: ${statusCode}`);
			return callback(new Error(ERROR_STATUS_CODE));
		}
		
		var wwwAuth = res.headers['www-authenticate'];
		if (!wwwAuth) {
			log(`www-authenticate: ${wwwAuth}`);
			return callback(new Error(ERROR_WRONG_WWW_AUTHENTICATE_HEADER));
		}
		
		var authValues = parseAuthenticateHeader(wwwAuth);
		var realm = authValues['Digest realm'];
		var qop = authValues['qop'];
		var nonce = authValues['nonce'];
		var username = option.username;
		var password = option.password;
		
		// HA1=MD5(username:realm:password)
		var ha1 = md5(`${username}:${realm}:${password}`);
		
		// HA2=MD5(method:digestURI)
		var ha2 = md5(`${method}:${path}`);
		
		// response=MD5(HA1:nonce:nonceCount:cnonce:qop:HA2)
		var nonceCount = '00000001';
		var cnonce = '0a4f113b';
		var response = md5(`${ha1}:${nonce}:${nonceCount}:${cnonce}:${qop}:${ha2}`);
		var authHeader = `Digest \
					username="${username}", \
					realm="${realm}", \
					nonce="${nonce}", \
					uri="${path}", \
					qop=${qop}, \
					nc=${nonceCount}, \
					cnonce="${cnonce}", \
					response="${response}"`;
					
		var reqTwoOption = {
			hostname: hostname,
			path: path,
			method: method,
			headers: {
				'Authorization': authHeader
			}
		};
		
		if (requestData) {
			reqTwoOption.headers['Content-Type'] = 'application/json';
			reqTwoOption.headers['Content-Length'] = requestData.length;
		}
		
		var reqTwo = r(reqTwoOption, function (res) {
			var statusCode = res.statusCode;
			if (statusCode >= 200 && statusCode < 300) {
				var result = '';
				res.setEncoding('utf8');
				res.on('data', function (chunk) {
					result += chunk;
				});
				res.on('end', function () {
					callback(null, result);
				});
			} else {
				log(`status code: ${statusCode}`);
				callback(statusCode);
			}
		});
		
		reqTwo.on('error', function (err) {
			log(err);
			callback(err);
		});
		
		if (requestData) {
			reqTwo.write(requestData);
		}
		reqTwo.end();
		
	});
	
	reqOne.on('error', function (err) {
		log(err);
		callback(err);
	});
	
	if (requestData) {
		reqOne.write(requestData);
	}
	reqOne.end();
}

function log(msg) {
	if (isDebug()) {
		console.log(delimiter);
		console.log(msg);
		console.log(delimiter);
	}
}

function parseAuthenticateHeader(val) {
	var regex = /(?:\s*,?\s*)(.+?)="(.+?)"/g;
	var result = {};
	var match = null;
	while ((match = regex.exec(val)) !== null) {
		result[match[1]] = match[2];
	}
	return result;
}

function md5(str) {
	var hash = crypto.createHash('md5');
	hash.update(str);
	return hash.digest('hex');
}

exports.request = request;
