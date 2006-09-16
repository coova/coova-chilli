/*
 * BROWSER BASED SMART CLIENT LIBRARY for Chillispot-Coova
 * V0.2
 * Copyright (C) Wesea SAS
 * Author: Yannick Deltroo
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to
 * the Free Software Foundation, Inc.
 * 51 Franklin Street, Fifth Floor, Boston, MA 
 * 02110-1301, USA.
 *
 */

/**********************************************************
 *                  CSPOTSession object                   *
 **********************************************************
 *                                                        *
 * This object stores session information, updated        *
 * from chillispot, after we've received fresh XML from   *
 * ChilliSpot.                                            *
 *                                                        *
 **********************************************************/

 _CSPOT_AUTHENTICATED   = 1  ;
 _CSPOT_UNAUTHENTICATED = 0  ;
 _CSPOT_PENDING         = 2  ;
 _CSPOT_UKNOWN          = -1 ;

function CSPOTSession () { // Constructor for CSPOTSession object

	this.state		= -1 ;	// user state ( AUTHENTICATED / UNAUTHENTICATED / UKNOWN )
	this.lastUpdate		= -1 ;  // Date of the last Update

	this.replyMessage	= -1 ;  // User-readable message sent by the radius server
	this.challenge		= -1 ;  // ChilliSpot generated challenge (hex string)

	
	this.startTime 		= -1 ;  // Unix Timestamp
	this.sessionTime	= -1 ;  // Duration of the session till now (in seconds) 
	this.timeout  		= -1 ;  // Optional : Maximum duration for this session
	this.timeLeft 		= -1 ;  // Optional : remaining time till the end of the session
	this.terminateTime 	= -1 ;  // Optional : Date for session termination

	this.acctInputOctets 	= -1 ;  // Chillispot volume info
	this.acctOutputOctets	= -1 ;  // Chillispot volume info
	this.maxInputOctets  	= -1 ;
	this.maxOutputOctets 	= -1 ;
	this.maxTotalOctets  	= -1 ;
}

/**********************************************************
 *                  CSPOTUser object                      *
 **********************************************************
 *                                                        *
 * This object must be instanciated in the user interface *
 *                                                        *
 * Constructor myuser = new CSPOTUser ( polling )         *
 *                                                        *
 * Properties                                             *
 *  - lang     : passed in logon URL                      *
 *  - userName : account User-Name                        *
 *  - password : account password                         *
 *  - state    : user current state                       *
 *  - interval : XML polling interval (in mseconds)       *
 *                                                        *
 * Methods:                                               *
 *  - connect()     (calls /prelogin & /logon)            *
 *  - disconnect()  (calls /logoff)                       *
 *  - refresh()     (calls /status)                       *
 *                                                        *
 * When these methods finish, they'll fire one of the     *
 * following events:                                      *
 *  - onUpdate()                                          *
 *  - onError()                                           *
 *                                                        *
 **********************************************************/

function CSPOTUser( cPolling ) {
	/***************************
	 *  class: CSPOTUser       *
	 *         properties      *
	/***************************/

        // PUBLIC
	this.lang     = "EN"		; // Default value for language (adds &lang=EN to logon URL)
	this.userName = ""		; // Radius User-Name
	this.password = ""		; // Radius Password
	this.host     = "192.168.182.1" ; // Chillispot host, default value
	this.port     = "3990"          ; // Chillispot port, default value
	this.state    =  _CSPOT_UKNOWN 	; 	

        // PRIVATE
	this.interval		= 10000 ;
	this.intervalID 	= 0  ;  

	// If polling value is passsed in the constructor
        // .... we'll use it

	if (cPolling) {

		this.interval = cPolling;
	}
	trace ("interval = " + this.interval);
	// Default error handling method (should be overloaded)

	this.onError = function ( err ) {
		trace ("CSPOTUser error: " + err );
	}

	/***********************************************
	 *   class: CSPOTUser                          *
	 *  method: refresh 	                       *
	 *          check status from chilli           *
         *          then invoke onUpate(CSPOTSession)  *
	/***********************************************/
	this.refresh = function() {

		zThis = this ;
		var status = new CSPOTQuery( "/status" );
		status.host = this.host;
		status.port = this.port;
		status.onError = this.onError ;
		
		status.onResponse = function (args , delay) {
							
			if ( args.state == _CSPOT_AUTHENTICATED ) { // User is authenticated
				
				if ( !zThis.intervalID ) { // The interval is not yet started. Let's start is now 
                        		zThis.intervalID = setInterval( zThis , "refresh" , zThis.interval ); 
					trace ("CSPOTUser : state = AUTHENTICATED, start polling every " + zThis.interval  + "ms, intervalID=" + zThis.intervalID );
				}
			}
			else if ( args.state == _CSPOT_UNAUTHENTICATED )  {  // User is not authenticated

				// Stop polling for refresh
				trace ("CSPOTUser : state = NOT AUTHENTICATED stop polling (intervalID="+ zThis.intervalID + ")");
				clearInterval (zThis.intervalID);
				zThis.intervalID = 0;

			}
			else if ( args.state ==  _CSPOT_UKNOWN ) { // State not updated. No <State> in chilli XML
				// Calling error handler
				this.onError("Cannot determine State from /status");
			}

			// Now calling handler
			zThis.state = args.state ;
			zThis.onUpdate(args);

		} // end status.onResponse

		// MAIN .refresh()
		status.go() ; 
		delete status ;

	} // End .refresh()

	/****************************************************
	 *   class: CSPOTUser                               *
	 *  method: disconnect 	                            *
	 *          will make a HTTP request to /logoff     *
         *          and then invoke onUpdate(CSPOTSession)  *
	 ****************************************************/
	this.disconnect = function () {

		zThis = this; 
		
		var logoff = new CSPOTQuery ("/logoff");
		logoff.host = this.host;
		logoff.port = this.port;
		logoff.onError = this.onError;

		logoff.onResponse = function (args) {

			if (args.state = _CSPOT_UNAUTHENTICATED ) { // Logoff succeeded
								    // Stop polling for status
				clearInterval(zThis.intervalID);
				zThis.intervalID = 0;
			}

			// now calling handler
			zThis.state = args.state ;
			zThis.onUpdate(args) ;
		}

		// MAIN disconnect
		logoff.go();
		delete logoff;
	}

	/***********************************************************************
	 *   class: CSPOTUser                                                  *
	 *  method: connect                                                    *
	 *          will try to logon the user (request to /prelogin & /logon) *
	 *	    then get the sessions status (/status)                     *
         *          and finally invoke on onUpdate(CSPOTSession)               *
	 ***********************************************************************/
         this.connect = connect;
}

function connect () {

	/************************/
	/* 1 - call prelogin    */
	/************************/
	zThis = this;

	var prelogin = new CSPOTQuery("/prelogin");
	prelogin.host = this.host;
	prelogin.port = this.port;

	prelogin.onResponse = function (session) {

   		var challenge = new String (session.challenge);
		if ( challenge == "" || challenge == -1 ) {
			trace("Challenge not found in prelogin" );
			zThis.onError("Challenge not found in prelogin");
			return;
		}

		trace ("Got CHAP-Challenge=" + challenge );

		if ( (typeof(zThis.userName) == undefined) || (zThis.userName=="") ) {
			trace ("CSPOTUser.userName is not defined");
			zThis.onError("UserName is not defined");
			return;
		}
		
		if ( (typeof(zThis.password) == undefined) || (zThis.userName=="") ) {
			trace ("CSPOTUser.password is not defined" );
			zThis.onError("password is not defined");
			return;
		}
		
			/*
			 *   CHAP Ident is hardcoded to \xFF because Javascript cannot handle \x00 strings
			 *   &ident=255 is passed in the logon URL so that chilli puts it in Chap-Password radius AV
			 *   
                         *              CHAP-Password = [ident] + MD5( ident + pass + chall);
		         *   
		         */


		var response = MD5.hex_md5( hexdecode("ff") +  zThis.password  + hexdecode(challenge) );
		trace ("password = " + zThis.password + " / reponse =" + response);

		var urlpath = "/logon?username=" + zThis.userName + "&response=" + response + "&ident=255";
		
		if (typeof(zThis.lang) != undefined ) {
			urlpath = urlpath + "&lang=" + zThis.lang ;
		}

		var logon = new CSPOTQuery(urlpath);
		logon.host = zThis.host
		logon.port = zThis.port;

		/************************/
		/* 2 - calling logon    */
		/************************/

		logon.onResponse = function (logonInfo) {
			trace("Entering logon.onResponse, state = " + logonInfo.state );
			// Store logon message to later overload postLogon message 
			logonMessage = logonInfo.replyMessage;

			/***************************/
			/* 3 - Successfull logon ? */
			/***************************/

			if (logonInfo.state == _CSPOT_AUTHENTICATED) { // Sucessfull logon
				trace ("Enetering postLogonStatus");
				/************************************
				 * 4 - get status info after logon  *
				 ************************************/
				var postLogonStatus = new CSPOTQuery("/status");
				postLogonStatus.host = zThis.host;
				postLogonStatus.port = zThis.port;
				
				postLogonStatus.onResponse = function (statusInfo) {


					if ( statusInfo.state == _CSPOT_AUTHENTICATED ) { // User is authenticated

						trace("CSPOTUser : postlognstatus, user is authenticated");

						if ( !zThis.intervalID ) { // The interval is not yet started. Let's start is now 
							zThis.intervalID = setInterval( zThis , "refresh" , zThis.interval ); 
							trace ("CSPOTUser : postLogonStatus, AUTHENTICATED, start polling every " + zThis.interval  + "ms, intervalID=" + zThis.intervalID );
						}
					}
					else if ( statusInfo.state == _CSPOT_UNAUTHENTICATED )  {  // User is not authenticated

						// Stop polling for refresh
						trace ("CSPOTUser : postLogonStatus,  NOT AUTHENTICATED stop polling (intervalID="+ zThis.intervalID + ")");
						clearInterval (zThis.intervalID);
						zThis.intervalID = 0;

					}
					else if ( statusInfo.state ==  _CSPOT_UKNOWN ) { // State not updated. No <State> in chilli XML
						// Calling error handler
						this.onError("Cannot determine State from /status");
					}

					// Reply-Message received in /logon response is more meaningful
					statusInfo.replyMessage = logonMessage;
					trace ("Reply-Message = " + logonMessage );

					// Now Call handler					
					zThis.state = statusInfo.state ;
					zThis.onUpdate(statusInfo);
					return;
				}

				postLogonStatus.go();
				delete postLogonStatus;
			} 
			/************************/
			/* 3bis - Logon Failed  */
			/************************/
			else if (logonInfo.state == _CSPOT_UNAUTHENTICATED ) { 
				trace ("CSPOTUser : logon failed, stop polling (intervalID="+ zThis.intervalID + ")");
				trace ("Reply-Message :" + logonInfo.replyMessage );
				clearInterval (zThis.intervalID);
				zThis.intervalID = 0;
				
				// Now call handler					
				zThis.state = logonInfo.state ;
				zThis.onUpdate(logonInfo);
				return;

			}
			else if (logonInfo.state == _CSPOT_PENDING ) { 
				/*
                                 * TODO
                                 */
			}

		} // end logon.onResponse handler

		// Calling logon
		logon.go();
		delete logon;

	}// end prelogin.onReponse

	// Calling prelogin
	prelogin.go(); 
	delete prelogin;
}

/***************************************************************
 *                  CSPOTQuery object                          *
 ***************************************************************
 * This object is only used by CSPOTUser, it should not        *
 * be used directly from the user interface.                   *
 *                                                             *
 * Makes a HTTP request uto Chillispot, using Flash XMLSocket  *
 * instead of buily-in HTTP (for better error processing)      *
 * The <ChilliSpotSession> fragment is parsed and stored in    *
 * a CSPOTSession object which is passed to the object handler *
 ***************************************************************/

function CSPOTQuery (cPath) {

	/************************
	 * Object Properties    *
         ************************/
	 this.host = "192.168.182.1";
         this.port = "3990" ;

        // Get input from constructor
	if (typeof (cPath) == "string") {
		this.path = cPath;
	}
	else {  // Default path if nothing given with constructor
		this.path = "/status";
	}


	this.url = "http://" + this.host + ":" + this.port  + this.path ;
	this.gotReply = false;

	this.id = _global.queryId + 1;
	 _global.queryId = _global.queryId + 1;
	 
	 trace ("query#"+ this.id + " " + this.url);

	/*************************************
	 *  Method : default error handling  *
         *                                   *
         *************************************/
	this.onError = function (errCode) {
		trace ("query#"+ this.id +"  Error code =" + errCode );
	}

	/*********************************************************
	 *  Method : go()                                        *
         *           Launch HTTP request                         *
         *           Will pass the XML message to process method *
         *********************************************************/

	this.go = function () {

		var zPath     	= this.path	;
		var zHost 	= this.host 	;
		var zPort 	= this.port	;
		var zId  	= this.id	;
		var zThis	= this 		;

		/********************
		 * Flash XML Socket *
	         ********************/

		mySocket		= new XMLSocket(); 
		mySocket.onClose 	= function () {

			  		  if ( zThis.gotReply ) {
					    //trace("query#"+zId+": socket closed" ); 
					  }
					  else { // the socket was closed without any content in the response \0
					    trace("query#"+zId+": socket closed on empty response. Likely cause: no Flash support in this ChilliSpot" ); 
					    zThis.onQuerryError ("empty response");
					  }
					} ;
		/******************************/
		/* mySocket.onConnect handler */
 		/******************************/
		mySocket.onConnect 	= function(success) {

				if (success) {

					//trace ("query#"+zId+" Socket established to " + zHost + ":" + zPort );
					httpGet = "GET " + zPath + " HTTP/1.0";
					//trace ("query#"+zId+" Sending > " +  httpGet);
					httpGet = httpGet +  "\r\n" ;

					httpUserAgent = "User-Agent: BBSC/1.0 (Flash;rev:5) Chillispot-Coova";
					//trace ("query#"+zId+" Sending > " +  httpUserAgent );
					httpUserAgent = httpUserAgent + "\r\n\r" ; 

					/* IMPORTANT
				         * 
					 * http request reaching the server must be terminated with \r\n\r\n
					 * but chillispot will replace \0 added by flash with \n (x0A)
				         * so we should terminate our request with \r\n\r only 
			                 *
	                		 * Note \r=CR=Carriage Return=13=x0D
				         *      \n=LF=Line Feed=10=x0A
					 */

					mySocket.send( httpGet + httpUserAgent );
				}
				else {
					/* TODO: we should probably add some retry mechanism here */

					now = new Date();
					delta = now.getTime() - takeoff.getTime()
					 if ( delta > 15000 ) { // It took sometime  to get there
						   trace ("query#"+zId+" failed socket to " +zHost+":"+zPort+" (Timeout). Host unreacheable" );
						   zThis.onError ("TCP Timeout");
				  	 }
					 else { // We arrived there rather quickly
						   trace ("query#"+zId+" Cannot open socket to "+zHost+":"+zPort+" (access denied, no IP on client ?)");	
					   	   zThis.onError ("Access denied");
					   }

					   
				} // End if/else (success)
		} ; // End onConnnect Handler

		/***************************/
		/* mySocket.onData handler */
 		/***************************/

		mySocket.onData 	= function(raw) { // Parsing the response to XML
						


						//trace ("query#"+zId+"  Response received (" + raw.length + " bytes)" );
						zThis.gotReply = true ;
							
						// Remove HTTP header and HTML from response text
						var xmlStart = raw.indexOf ("<WISPAccessGatewayParam");
						var xmlText  = raw.substring ( xmlStart );

						landing = new Date();

						var token = "</WISPAccessGatewayParam>";
						var xmlEnd = xmlText.indexOf ( token );
						var offset = token.length + 1 ; 
						xmlText = xmlText.substring( 0 , xmlEnd + offset );

						//trace ("--------------        RAW HTTP RESPONSE       ------------");
						//trace (raw  );
						//trace ("----------------------------------------------------------");

						
						// Removing Carriage return (only here to clean XML debug output )
						var tmp = xmlText ; 
						for ( i=0 ;  i < tmp.length ; i++) {
							if (tmp.charCodeAt(i) == 13 ) {

								tmp = tmp.substring(0,i) + " " + tmp.substring(i+1,xmlText.length-1);

							}
						}
						
						xmlText = tmp;

						// Parse xmlText to an XML object
						xmlObject = new XML();
						xmlObjec.ignoreWhite = true;
					 	xmlObject.parseXML( xmlText );

						if (!xmlObject.toString()) {
							trace ("--------------  XML MESSAGE ------------");
							trace (xmlObject.toString());
							trace ("----------------------------------------------------");

							// Now Calling process method
							zThis.process(xmlObject);

							return ;
						}
						else {
							trace("query#"+zId+" XML parse error " . xmlObject.status  );
							zThis.onError("XML parse Error");
						}

					}; // End onData handler

		/*****************/
		/* go() : MAIN   */
 		/*****************/

		//trace ("query#"+zId+" Opening socket to " + zHost + ":" + zPort );

		// Opening socket
		takeoff = new Date();
		if (!mySocket.connect( zHost , zPort )) {
			trace ("query#"+zId+" failed socket to "+zHost+":"+zPort+" wrong host:port (port must be>1024)" );
			zThis.onError("wrong port");
		}
		return ;

	}; // end go method


	/********************************************************************
	 *  Method : process()                                              *
         *           Chillispot XML message parsing                         *
         *           Will call onUpdate() with a session object as argument *
         ********************************************************************/

	this.process = function (arg) { // WISPr message XML Object is passed as argument

	  //trace ("query#"+ this.id +" Parsing ChilliSpotSession tags");	
	  var session = new CSPOTSession(); // session is initialized with default values
		
	  for (i in arg.firstChild.childNodes) {
			
		section =  arg.firstChild.childNodes[i].nodeName ; 
		if ( section == "ChilliSpotSession" ) {

		   //trace("  Found is a ChilliSpotSession XML message");
		   for (j in arg.firstChild.childNodes[i].childNodes) {

			var attr =   arg.firstChild.childNodes[i].childNodes[j].nodeName;
			var value =  arg.firstChild.childNodes[i].childNodes[j].firstChild.nodeValue;

			switch (attr) {

				case "State" :			session.state = value;
								//trace("     status = " + session.state );
								break ;
								
				case "ReplyMessage" :		session.replyMessage = value;
								//trace("     replyMessage = " + session.replyMessage );
								break ;
								
				case "Challenge" :		session.challenge = value;
								//trace("     challenge = " + session.challenge);
								break ;

				case "StartTime" :		session.startTime = parseInt(value);
								//trace("     startTime = " + session.startTime );
								break ;

				case "SessionTime" :		session.sessionTime = parseInt(value);
								//trace("     sessionTime = " + session.sessionTime );
								break ;

				case "Timeout" :		session.timeout = parseInt(value);
								//trace("     sessionTimeout = " + session.timeout  );
								break ;

				case "TimeLeft" :		session.timeLeft = parseInt(value);
								//trace("     timeLeft = " + session.timeLeft );
								break ;	

				case "Terminatetime" :		session.terminateTime = parseInt(value);
								//trace("     terminateTime = " + session.terminateTime );
								break ;

				case "InputOctets" :		session.inputOctets = parseInt(value);
								//trace("     inputOctets = " + session.inputOctets );
								break ;

				case "OutputOctets" :		session.outputOctets = parseInt(value);
								//trace("     outputOctets = " + session.outputOctets );
								break ;

				case "MaxInputOctets" :		session.maxInputOctets = parseInt(value);
								//trace("     maxInputOctets = " + session.maxInputOctets );
								break ;

				case "MaxOutputOctets" :	session.maxOutputOctets = parseInt(value);
								//trace("     maxOutputOctets = " + session.maxOutputOctets );
								break ;

				case "MaxTotalOctets" :		session.maxTotalOctets = parseInt(value);
								//trace("     maTotalOctets = " + session.maxTotalOctets );
								break ;

				case NULL:			break ;

				default : 			//trace("     Ignored : " + attr + "=" + value );

				} // End switch
			} // End for
		} // End if ChilliSpotSession

		else if ( section == NULL ) {
			// Ignore NULL sections
		}
		else { 
			// Unkown section
			//trace("Unknow section :" + section );
		} 

	} // End in firstChild.childNodes

	// Now Calling the onUpdate method with the session object as parameter
	var now = new Date();

	netDelay = (landing.getTime() - takeoff.getTime())/2 + now.getTime() - landing.getTime();
	//trace ("Network & processing delay = " + netDelay );

	this.onResponse(session , netDelay );

    } // End process method

} // end query object constructor
