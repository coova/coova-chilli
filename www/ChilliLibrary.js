/****************************************************/
/*                 ChilliLibrary                    */
/*                                                  */
/* Creates three global objects:                    */
/*    - ChilliController                            */
/*    - ChilliClock                                 */
/*    - ChilliJSON                                  */
/*                                                  */
/* Version 2.0 Copyright (C) Yannick Deltroo 2007   */
/* Distributed under the BSD License                */
/****************************************************/

// TODO: use constants for clientState (AUTH/NOTAUTH/PENDING)

var ChilliController = new Object();

/* Communication with Chilli daemon: Default values */
ChilliController.interval = 30 ;
ChilliController.host     = "192.168.182.1" ;
ChilliController.port     = 3990            ;
ChilliController.ssl      = false           ; // Use SSL to communucate with Chilli?

/* Communications with uamService : default values */
ChilliController.uamService = false ; // e.g. 'https://mysite.com/chilli.php'

/* Default ident (hex encoded string) for CHAP-Password calculations */
ChilliController.ident = '00' ; // e.g. 'ff' or '00'

/* Initializing session and accounting sections */
ChilliController.session     = -1 ;
ChilliController.accounting  = -1 ;
ChilliController.clientState = -1 ;
ChilliController.command     = -1 ;

/* calculate the root of command URLs */
ChilliController.urlRoot= function () {

	var protocol = ( ChilliController.ssl ) ? "https" : "http" ;
	return protocol + '://' + ChilliController.host + ':' + ChilliController.port + '/json/' ;
}

/* Default event handlers */
ChilliController.onUpdate = function ( cmd, state ) {
	alert('Default onUpdate handler. cmd = ' + cmd );
}

ChilliController.onError = function ( str ) {
	log ( '>> Default Error Handler<<\nYou should write your own\n\n' + str )
}

ChilliController.formatBytes = function ( bytes ) {
    return bytes + ' bytes';
}

ChilliController.formatTime = function ( sec, zeroReturn ) {
    if (sec == null) return "Not available";
    if (zeroReturn && sec == 0) return zeroReturn;
    return sec + ' sec';
}

/*******************************/
/*  ChilliController METHODS   */
/*******************************/

/* logon()    */
ChilliController.logon = function ( username , password )  {

	if ( typeof(username) !== 'string') ChilliController.onError( 1 , "Missing username (or incorrect type)" ) ;
	if ( typeof(password) !== 'string') ChilliController.onError( 2 , "Missing password (or incorrect type)" ) ;

	log ( 'ChilliController.logon( "' + username + '" , "' + password + ' " )' );

	ChilliController.command = 'logon';

	/* TODO: Should check if challenge has expired and possiblity get a new home */
	challenge = ChilliController.challenge ;
	log ('ChilliController.logon: challenge = ' + challenge );

	if ( ChilliController.uamService ) { /* MD5 CHAP will be calculated by uamService */

		log ('Logon using uamService (external MD5 CHAP)');

		// Build command URL
		var url = ChilliController.uamService + '?username=' + username +'&password=' + password +'&challenge=' + challenge ;

		if (ChilliController.queryObj && ChilliController.queryObj['userurl']) {
		    url += '&userurl='+ChilliController.queryObj['userurl'];
		}

		// Make uamService request
		ChilliJSON.onError     = ChilliController.onError    ;
		ChilliJSON.onJSONReady = ChilliController.processUAM ;

		ChilliController.clientState = 2 ; // AUTH_PENDING
		ChilliJSON.get( url ) ;

	}
	else {	/* non uamService, calculate MD5 CHAP locally */

		log ('Logon with local MD5 CHAP calculation');

		var myMD5 = new ChilliMD5();
		var chappassword = myMD5.chap ( ChilliController.ident , password , challenge );
		log ( 'Calculating CHAP-Password = ' + chappassword );

		// Build command URL
		var url = ChilliController.urlRoot() + 'logon?username=' + username + '&response='  + chappassword;

		if (ChilliController.queryObj && ChilliController.queryObj['userurl']) {
		    url += '&userurl='+ChilliController.queryObj['userurl'];
		}

		// Make logon  request
		ChilliJSON.onError     = ChilliController.onError     ;
		ChilliJSON.onJSONReady = ChilliController.processJSON ;

		ChilliController.clientState = 2 ; // AUTH_PENDING
		ChilliJSON.get ( url ) ;
	}
}

/* METHOD: refresh()    */
ChilliController.refresh = function () {

	ChilliController.command = 'refresh';

	// Make status request
	ChilliJSON.onError     = ChilliController.onError     ;
	ChilliJSON.onJSONReady = ChilliController.processJSON ;

	url = ChilliController.urlRoot() + 'status' ;
	ChilliJSON.get( url );
}

/* METHOD: logoff()    */
ChilliController.logoff = function () {

	ChilliController.command = 'logoff';

	// Make status request
	ChilliJSON.onError     = ChilliController.onError     ;
	ChilliJSON.onJSONReady = ChilliController.processJSON ;

	url = ChilliController.urlRoot() + 'logoff' ;
	ChilliJSON.get( url );
}

/* METHOD: processJSON reply from Chilli daemon    */
ChilliController.processJSON = function ( resp ) {

	var sid = new String;
	if ( resp.sessionId ) sid = '( sessionId = ' + resp.sessionId  + ' )';
	if ( sid.length !== 0 ) log('ChilliController.processJSON: Processing reply. ' + sid );

	if ( typeof (resp.message)   == 'string' ) ChilliController.message   = resp.message   ;
	if ( typeof (resp.sessionId) == 'string' ) ChilliController.sessionId = resp.sessionId ;
	if ( typeof (resp.challenge) == 'string' ) ChilliController.challenge = resp.challenge ;

	if ( typeof ( resp.location ) == 'object' ) {
		ChilliController.location = resp.location;
	}

	if ( typeof ( resp.redir ) == 'object' ) {
		ChilliController.redir = resp.redir;
	}

	if ( typeof ( resp.accounting ) == 'object' ) {
		ChilliController.accounting = resp.accounting ;
	}

	if ( (typeof ( resp.session ) == 'object') && ( ChilliController.clientState!==1 ) && ( resp.clientState===1 ) ) {
		ChilliController.session = resp.session ;
	}

	var previousState = ChilliController.clientState;

	if ( resp.clientState == 0 || resp.clientState == 1 ) {
		ChilliController.clientState = resp.clientState;
	}
	else {
		this.onError("Incorrect clientState found in JSON reply");
	}

	// Lastly... call the event handler
	log ('ChilliController.processJSON: Calling onUpdate. clienState = ' + ChilliController.clientState);
	ChilliController.onUpdate( ChilliController.command, previousState );
}

// TODO: rename uamserver to uamservice (for webservice ?)

/* processUAM json reply from uamserver */
/* and then send logon to Chilli        */
ChilliController.processUAM = function ( resp ) {

	// Build command URL
	if ( typeof (resp.response) === 'string' ) { 
	   var url = ChilliController.urlRoot() + 'logon?username=' + resp.username + '&response=' + resp.response ;
	}
	else if ( typeof (res.password) === 'string' ) {
	   var url = ChilliController.urlRoot() + 'logon?username=' + resp.username + '&password=' + resp.password ;
	}

	// Make logon  request
	ChilliJSON.onError     = ChilliController.onError     ;
	ChilliJSON.onJSONReady = ChilliController.processJSON ;

	ChilliController.clientState = 2 ; // AUTH_PENDING
	ChilliJSON.get( url ) ;
}

/****************************************/
/* ChilliJSON object                    */ 
/* Implements cross domain hack         */
/****************************************/

var ChilliJSON = new Object();

ChilliJSON.timeout   = 20000 ;
ChilliJSON.pending   = 0 ;
ChilliJSON.node      = 0 ;
ChilliJSON.timestamp = 0 ;
ChilliJSON.expired   = function () {

		if ( ChilliJSON.node.text ) log ('ChilliJSON: reply content \n' + ChilliJSON.node.text );
		else log ('ChilliJSON: request timed out (or reply is not valid JS)');

		clearInterval ( ChilliJSON.timer ) ;

		// remove node (may exist if we received non JS text)
		if ( typeof (ChilliJSON.node) !== 'number' ) document.getElementsByTagName('head')[0].removeChild(ChilliJSON.node);
		ChilliJSON.pending = 0;

		/* TODO: Implement some kind of retry mechanism here ... */

		ChilliJSON.onError('JSON request timed out (or reply is not valid)');
}

ChilliJSON.reply = function  ( raw ) {


		if ( ChilliJSON.timestamp ) {
			var now = new Date();
			var flightTime = now.getTime() - ChilliJSON.timestamp;
			log ( 'ChilliJSON: JSON reply received in ' + flightTime + ' ms\n' + dumpObject ( raw )  );
		}


		clearInterval ( ChilliJSON.timer ) ;
		ChilliJSON.pending = 0 ;
		ChilliJSON.started = 0 ;

		if ( typeof (ChilliJSON.node) !== 'number' ) document.getElementsByTagName('head')[0].removeChild ( ChilliJSON.node );
		ChilliJSON.node = 0;

                /* TODO: should clean-up raw JSON with a real parser HERE before passing it over */
		ChilliJSON.onJSONReady( raw ) ;
}

ChilliJSON.get = function ( url ) {

		if ( typeof(url) == "string" ) {
		        ChilliJSON.url = url  ;
		}
		else {
			log ( "ChilliJSON:error:Incorrect url passed to ChilliJSON.get():" + url );
			ChilliJSON.onError ( "Incorrect url passed to ChilliJSON.get() " );
			return ;
		}

		if ( ChilliJSON.pending == 1 ) {

			log('logon: There is a request already running');

			// ChilliJSON.pending is not correctly set in IE7
			// remove this line :
			//ChilliJSON.onError ("Please wait for the previous request to complete.");	
		}

		/* Using interval instead of timeout to support Flash 5,6,7 */
		ChilliJSON.timer     = setInterval ( 'ChilliJSON.expired()' , ChilliJSON.timeout ) ; 
		var now = new Date();
		ChilliJSON.timestamp = now.getTime() ;

		var scriptElement  = document.createElement('script');
		scriptElement.type = 'text/javascript';

		var c = new String();
		if ( this.url.indexOf('?') === -1 ) { 
			c = '?' ;
		}
		else {
			c = '&' ;
		}

		scriptElement.src = ChilliJSON.url + c + 'callback=ChilliJSON.reply';
		scriptElement.src += '&'+Math.random();
		
		// Adding the node that will trigger the HTTP request
		ChilliJSON.node = document.getElementsByTagName('head')[0].appendChild(scriptElement);
		ChilliJSON.pending = 1 ; 

		log ('ChilliJSON: getting ' + ChilliJSON.url + ' . Waiting for reply ...');
}

/****************************************/
/* Clock object                         */ 
/****************************************/

var ChilliClock = new Object ();
ChilliClock.timerId   = 0     ;
ChilliClock.isStarted = false ;
ChilliClock.value     = 0     ;

ChilliClock.increment = function () {
	ChilliClock.value =  ChilliClock.value + 1 ;
	ChilliClock.onChange ( ChilliClock.value ) ;
}

ChilliClock.resync = function ( newval ) {
	clearInterval ( ChilliClock.timerId )  ;
	ChilliClock.value = parseInt( newval ) ;
	ChilliClock.timerId = setInterval ( ChilliClock.increment , 1000 );
	ChilliClock.isStarted = true ;		
}

ChilliClock.stop = function () {
	clearInterval ( ChilliClock.timerId )  ;
	ChilliClock.timerId = 0 ;
	ChilliClock.isStarted = false ;	
}

/****************************************/
/* Logging function for ActionScript    */ 
/* and FireBug console                  */
/****************************************/
function log( msg , messageLevel ) {

	if ( typeof(trace)=="function") {
		// ActionScript trace
		trace ( msg );
	}
	else if ( typeof(console)=="object") {
		// FireBug console
		console.debug ( msg );
	}
}

function dumpObject ( obj ) {

	var str = new String ;

	for (var key in obj ) {
	
		str = str + "    " + key + " = " + obj[key] + "\n" ;

		if ( typeof ( obj[key] ) == "object" ) {
			for ( var key2 in obj[key] ) {
				str = str + "      " + key2 + " = "  + obj[key][key2] + "\n" ;
			}
		}

	}

	return str;
}

/*
 * A JavaScript implementation of the RSA Data Security, Inc. MD5 Message
 * Digest Algorithm, as defined in RFC 1321.
 * Version 2.1 Copyright (C) Paul Johnston 1999 - 2002.
 * Other contributors: Greg Holt, Andrew Kepert, Ydnar, Lostinet
 * Distributed under the BSD License
 * See http://pajhome.org.uk/crypt/md5 for more info.
 *
 * chappassword, hex2binl, str2hex and added by Y.DELTROO
 * Copyright (C) 2007
 * Distributed under the BSD License
 *
 */
function ChilliMD5() {

	var hexcase = 0;  /* hex output format. 0 - lowercase; 1 - uppercase        */
	var b64pad  = ""; /* base-64 pad character. "=" for strict RFC compliance   */
	var chrsz   = 8;  /* bits per input character. 8 - ASCII; 16 - Unicode      */

	this.hex_md5 = function (s){ return binl2hex(core_md5(str2binl(s), s.length * chrsz));}

	this.chap = function ( hex_ident , str_password , hex_chal ) {

		//  Convert everything to hex encoded strings
		var hex_password =  str2hex ( str_password );

		// concatenate hex encoded strings
		var hex   = hex_ident + hex_password + hex_chal;

		// Convert concatenated hex encoded string to its binary representation
		var bin   = hex2binl ( hex ) ;

		// Calculate MD5 on binary representation
		var md5 = core_md5( bin , hex.length * 4 ) ; 

		return binl2hex( md5 );
	}

	function core_md5(x, len)
	{
	  x[len >> 5] |= 0x80 << ((len) % 32);
	  x[(((len + 64) >>> 9) << 4) + 14] = len;

	  var a =  1732584193;
	  var b = -271733879;
	  var c = -1732584194;
	  var d =  271733878;

	  for(var i = 0; i < x.length; i += 16)
	  {
		var olda = a;
		var oldb = b;
		var oldc = c;
		var oldd = d;

		a = md5_ff(a, b, c, d, x[i+ 0], 7 , -680876936);
		d = md5_ff(d, a, b, c, x[i+ 1], 12, -389564586);
		c = md5_ff(c, d, a, b, x[i+ 2], 17,  606105819);
		b = md5_ff(b, c, d, a, x[i+ 3], 22, -1044525330);
		a = md5_ff(a, b, c, d, x[i+ 4], 7 , -176418897);
		d = md5_ff(d, a, b, c, x[i+ 5], 12,  1200080426);
		c = md5_ff(c, d, a, b, x[i+ 6], 17, -1473231341);
		b = md5_ff(b, c, d, a, x[i+ 7], 22, -45705983);
		a = md5_ff(a, b, c, d, x[i+ 8], 7 ,  1770035416);
		d = md5_ff(d, a, b, c, x[i+ 9], 12, -1958414417);
		c = md5_ff(c, d, a, b, x[i+10], 17, -42063);
		b = md5_ff(b, c, d, a, x[i+11], 22, -1990404162);
		a = md5_ff(a, b, c, d, x[i+12], 7 ,  1804603682);
		d = md5_ff(d, a, b, c, x[i+13], 12, -40341101);
		c = md5_ff(c, d, a, b, x[i+14], 17, -1502002290);
		b = md5_ff(b, c, d, a, x[i+15], 22,  1236535329);

		a = md5_gg(a, b, c, d, x[i+ 1], 5 , -165796510);
		d = md5_gg(d, a, b, c, x[i+ 6], 9 , -1069501632);
		c = md5_gg(c, d, a, b, x[i+11], 14,  643717713);
		b = md5_gg(b, c, d, a, x[i+ 0], 20, -373897302);
		a = md5_gg(a, b, c, d, x[i+ 5], 5 , -701558691);
		d = md5_gg(d, a, b, c, x[i+10], 9 ,  38016083);
		c = md5_gg(c, d, a, b, x[i+15], 14, -660478335);
		b = md5_gg(b, c, d, a, x[i+ 4], 20, -405537848);
		a = md5_gg(a, b, c, d, x[i+ 9], 5 ,  568446438);
		d = md5_gg(d, a, b, c, x[i+14], 9 , -1019803690);
		c = md5_gg(c, d, a, b, x[i+ 3], 14, -187363961);
		b = md5_gg(b, c, d, a, x[i+ 8], 20,  1163531501);
		a = md5_gg(a, b, c, d, x[i+13], 5 , -1444681467);
		d = md5_gg(d, a, b, c, x[i+ 2], 9 , -51403784);
		c = md5_gg(c, d, a, b, x[i+ 7], 14,  1735328473);
		b = md5_gg(b, c, d, a, x[i+12], 20, -1926607734);

		a = md5_hh(a, b, c, d, x[i+ 5], 4 , -378558);
		d = md5_hh(d, a, b, c, x[i+ 8], 11, -2022574463);
		c = md5_hh(c, d, a, b, x[i+11], 16,  1839030562);
		b = md5_hh(b, c, d, a, x[i+14], 23, -35309556);
		a = md5_hh(a, b, c, d, x[i+ 1], 4 , -1530992060);
		d = md5_hh(d, a, b, c, x[i+ 4], 11,  1272893353);
		c = md5_hh(c, d, a, b, x[i+ 7], 16, -155497632);
		b = md5_hh(b, c, d, a, x[i+10], 23, -1094730640);
		a = md5_hh(a, b, c, d, x[i+13], 4 ,  681279174);
		d = md5_hh(d, a, b, c, x[i+ 0], 11, -358537222);
		c = md5_hh(c, d, a, b, x[i+ 3], 16, -722521979);
		b = md5_hh(b, c, d, a, x[i+ 6], 23,  76029189);
		a = md5_hh(a, b, c, d, x[i+ 9], 4 , -640364487);
		d = md5_hh(d, a, b, c, x[i+12], 11, -421815835);
		c = md5_hh(c, d, a, b, x[i+15], 16,  530742520);
		b = md5_hh(b, c, d, a, x[i+ 2], 23, -995338651);

		a = md5_ii(a, b, c, d, x[i+ 0], 6 , -198630844);
		d = md5_ii(d, a, b, c, x[i+ 7], 10,  1126891415);
		c = md5_ii(c, d, a, b, x[i+14], 15, -1416354905);
		b = md5_ii(b, c, d, a, x[i+ 5], 21, -57434055);
		a = md5_ii(a, b, c, d, x[i+12], 6 ,  1700485571);
		d = md5_ii(d, a, b, c, x[i+ 3], 10, -1894986606);
		c = md5_ii(c, d, a, b, x[i+10], 15, -1051523);
		b = md5_ii(b, c, d, a, x[i+ 1], 21, -2054922799);
		a = md5_ii(a, b, c, d, x[i+ 8], 6 ,  1873313359);
		d = md5_ii(d, a, b, c, x[i+15], 10, -30611744);
		c = md5_ii(c, d, a, b, x[i+ 6], 15, -1560198380);
		b = md5_ii(b, c, d, a, x[i+13], 21,  1309151649);
		a = md5_ii(a, b, c, d, x[i+ 4], 6 , -145523070);
		d = md5_ii(d, a, b, c, x[i+11], 10, -1120210379);
		c = md5_ii(c, d, a, b, x[i+ 2], 15,  718787259);
		b = md5_ii(b, c, d, a, x[i+ 9], 21, -343485551);

		a = safe_add(a, olda);
		b = safe_add(b, oldb);
		c = safe_add(c, oldc);
		d = safe_add(d, oldd);
	  }
	  return Array(a, b, c, d);

	}
	function md5_cmn(q, a, b, x, s, t)
	{
	  return safe_add(bit_rol(safe_add(safe_add(a, q), safe_add(x, t)), s),b);
	}
	function md5_ff(a, b, c, d, x, s, t)
	{
	  return md5_cmn((b & c) | ((~b) & d), a, b, x, s, t);
	}
	function md5_gg(a, b, c, d, x, s, t)
	{
	  return md5_cmn((b & d) | (c & (~d)), a, b, x, s, t);
	}
	function md5_hh(a, b, c, d, x, s, t)
	{
	  return md5_cmn(b ^ c ^ d, a, b, x, s, t);
	}
	function md5_ii(a, b, c, d, x, s, t)
	{
	  return md5_cmn(c ^ (b | (~d)), a, b, x, s, t);
	}
	function safe_add(x, y)
	{
	  var lsw = (x & 0xFFFF) + (y & 0xFFFF);
	  var msw = (x >> 16) + (y >> 16) + (lsw >> 16);
	  return (msw << 16) | (lsw & 0xFFFF);
	}
	function bit_rol(num, cnt)
	{
	  return (num << cnt) | (num >>> (32 - cnt));
	}

	function str2binl(str)
	{
	  var bin = Array();
	  var mask = (1 << chrsz) - 1;
	  for(var i = 0; i < str.length * chrsz; i += chrsz)
		bin[i>>5] |= (str.charCodeAt(i / chrsz) & mask) << (i%32);
	  return bin;
	}

	function binl2hex(binarray)
	{
	  var hex_tab = hexcase ? "0123456789ABCDEF" : "0123456789abcdef";
	  var str = "";
	  for(var i = 0; i < binarray.length * 4; i++)
	  {
		str += hex_tab.charAt((binarray[i>>2] >> ((i%4)*8+4)) & 0xF) +
			   hex_tab.charAt((binarray[i>>2] >> ((i%4)*8  )) & 0xF);
	  }
	  return str;
	}

	function str2hex ( str )
	{
		var hex_tab = hexcase ? "0123456789ABCDEF" : "0123456789abcdef";
		var hex = new String;
		for ( var i=0 ; i<str.length ; i++)
		{
			/* TODO: adapt this if chrz=16   */
			val = str.charCodeAt(i);
			hex = hex + hex_tab.charAt( val/16 );
			hex = hex + hex_tab.charAt( val%16 );
		}
		return hex;
	}

	function hex2binl ( hex )
	{
		//  Clean-up hex encoded input string
		hex = hex.toLowerCase() ;
		hex = hex.replace( / /g , "");

		var bin = Array();

		// Transfrom to array of integers (binary representation) 
		for ( i=0 ; i < hex.length*4   ; i=i+8 ) 
		{
			octet =  parseInt( hex.substr( i/4 , 2) , 16) ;
			bin[i>>5] |= ( octet & 255 ) << (i%32);
		}

		return bin;
	}
	
} // end of ChilliMD5 constructor
