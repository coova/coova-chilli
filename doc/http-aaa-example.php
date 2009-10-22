<?php
/* 
 * Copyright (C) 2009 Coova Technologies, LLC.
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 * 
 */


// == start main ==

// globals for convenience
global $dblink;
global $hotspot_ap;
global $hotspot_network;
global $hotspot_user;
global $hotspot_device;
global $hotspot_code;
global $hotspot_session;

// initialize globals
$hotspot_ap = false;
$hotspot_network = false;
$hotspot_user = false;
$hotspot_device = false;
$hotspot_code = false;
$hotspot_session = false;

$dblink = db_open();

// Look up access point based on MAC address
$hotspot_ap = get_ap();
if (!is_array($hotspot_ap) || !isset($hotspot_ap['network_id'])) {
  echo 'Error: access point is not configured correctly';
  exit;
}

// Load the network that owns the access point to get uamsecret
$hotspot_network = get_network();
if (!is_array($hotspot_network) || !isset($hotspot_network['id'])) {
  echo 'Error: network is not configured correctly';
  exit;
}

// Verify the query string parameters with uamsecret
check_url();

if ($_GET['stage'] == 'login') {

  if      ($_GET['service'] == 'login')  do_login_service();    // Standard login
  else if ($_GET['service'] == 'framed') do_macauth_service();  // MAC authentication
  else if ($_GET['service'] == 'admin')  do_admin_service();    // Admin-User session
  else echo "Auth: 0\n";

} else if ($_GET['stage'] == 'counters') {

  do_accounting();

} else if ($_GET['stage'] == 'register') {

  do_register();

}

db_close();

// == end main ==


// == functions ==

function set_attribute         ($n, &$a, $v, $o = true) { if ($o || !isset($a[$n])) $a[$n]=$v; }
function set_idle_timeout      (&$a, $v, $o = true) { set_attribute('Idle-Timeout',$a,$v,$o); }
function set_reply_message     (&$a, $v, $o = true) { set_attribute('Reply-Message',$a,$v,$o); } 
function set_session_timeout   (&$a, $v, $o = true) { set_attribute('Session-Timeout',$a,$v,$o); } 
function set_interim_interval  (&$a, $v, $o = true) { set_attribute('Acct-Interim-Interval',$a,$v,$o); } 
function set_max_total_octets  (&$a, $v, $o = true) { set_attribute('ChilliSpot-Max-Total-Octets',$a,$v,$o); } 
function set_max_input_octets  (&$a, $v, $o = true) { set_attribute('ChilliSpot-Max-Input-Octets',$a,$v,$o); } 
function set_max_output_octets (&$a, $v, $o = true) { set_attribute('ChilliSpot-Max-Output-Octets',$a,$v,$o); } 
function set_max_total_kbytes  (&$a, $v, $o = true) { set_attribute('ChilliSpot-Max-Total-Octets',$a,($v*1000),$o); } 
function set_max_input_kbytes  (&$a, $v, $o = true) { set_attribute('ChilliSpot-Max-Input-Octets',$a,($v*1000),$o); } 
function set_max_output_kbytes (&$a, $v, $o = true) { set_attribute('ChilliSpot-Max-Output-Octets',$a,($v*1000),$o); } 
function set_redirection_url   (&$a, $v, $o = true) { set_attribute('WISPr-Redirection-URL',$a,$v,$o); } 

function set_max_bandwidth_up_bit_sec     (&$a, $v, $o = true) { set_attribute('WISPr-Bandwidth-Max-Up',$a,$v,$o); } 
function set_max_bandwidth_down_bit_sec   (&$a, $v, $o = true) { set_attribute('WISPr-Bandwidth-Max-Down',$a,$v,$o); } 
function set_max_bandwidth_up_kbit_sec    (&$a, $v, $o = true) { set_attribute('ChilliSpot-Bandwidth-Max-Up',$a,$v,$o); } 
function set_max_bandwidth_down_kbit_sec  (&$a, $v, $o = true) { set_attribute('ChilliSpot-Bandwidth-Max-Down',$a,$v,$o); } 
function set_max_bandwidth_up_kbyte_sec   (&$a, $v, $o = true) { set_attribute('ChilliSpot-Bandwidth-Max-Up',$a,($v*8),$o); } 
function set_max_bandwidth_down_kbyte_sec (&$a, $v, $o = true) { set_attribute('ChilliSpot-Bandwidth-Max-Down',$a,($v*8),$o); } 
function set_max_bandwidth_up_mbyte_sec   (&$a, $v, $o = true) { set_attribute('ChilliSpot-Bandwidth-Max-Up',$a,($v*8000),$o); } 
function set_max_bandwidth_down_mbyte_sec (&$a, $v, $o = true) { set_attribute('ChilliSpot-Bandwidth-Max-Down',$a,($v*8000),$o); } 

function format_attributes(&$attrs) {
  foreach ($attrs as $n => $v) {
    echo "$n:$v\n";
  }
}

function do_auth_accept($attrs = false) {

  do_acct_status('auth');

  echo "Auth: 1\n";
  if ($attrs) format_attributes($attrs);
}

function do_auth_reject($attrs = false) {
  echo "Auth: 0\n";
  if ($attrs) format_attributes($attrs);
}

function login_user(&$attrs) {
  network_attributes($attrs);
  ap_attributes($attrs);
  user_attributes($attrs);
  do_auth_accept($attrs);
}

function login_code(&$attrs) {
  network_attributes($attrs);
  ap_attributes($attrs);
  code_attributes($attrs);
  do_auth_accept($attrs);
}

function login_device(&$attrs) {
  network_attributes($attrs);
  ap_attributes($attrs);
  device_attributes($attrs);
  do_auth_accept($attrs);
}

function session_key() {
  return str_replace(array('-','.'),array(),$_GET['sessionid'].$_GET['ap'].$_GET['mac'].$_GET['ip'].$_GET['user']);
}

function do_macauth_service() {
  $attrs = array();
  $device = get_device();

  if ($device['always_authorized']) {
    login_device($attrs);
  } else {
    do_auth_reject($attrs);
  }
}

function do_login_service() {
  $attrs = array();
  $device = get_device();

  $login_func = 'login_user';
  $user_or_code = get_user();

  if (!$user_or_code) {
    $login_func = 'login_code';
    $user_or_code = get_code();
  }

  if (is_array($user_or_code)) {
    if (isset($_GET['chap_id'])) {

      // CHAP Challenge/Response Validation
      $chal = pack('H32', $_GET['chap_chal']);
      $check = md5("\0" . $user_or_code['password'] . $chal);

      if ($check == $_GET['chap_pass']) {
	$login_func($attrs);
	return;
      }
    }
    else if ($user_or_code['password'] == $_GET['pass']) {
      $login_func($attrs);
      return;
    }
  }

  set_reply_message($attrs, "Either your username or password did not match our records.");
  do_auth_reject($attrs);
}

function do_admin_service() {
  $attrs = array();
  set_interim_interval($attrs, 300);
  do_auth_accept($attrs);
}

function do_acct_status($status) {

  $do_admin_acct = false; // Change to 'true', if desired

  if (get_device() || $do_admin_acct) {

    if ($status == 'update') {
      
      update_session();
      
    } else if ($status == 'start') {
      
      start_session();
      
    } else if ($status == 'stop') {
      
      stop_session();

    } else if ($status == 'auth') {
      
      auth_session();
      
    }
  }
}

function do_accounting() {
  $attrs = array();

  do_acct_status($_GET['status']);

  echo "Ack: 1\n";
  if ($attrs) format_attributes($attrs);
}

function check_url() {
  global $hotspot_network;

  $uamsecret = $hotspot_network['uamsecret'];

  $md = $_GET['md'];

  $check = (empty($_SERVER['HTTPS']) ? 'http' : 'https').'://'.
    $_SERVER['SERVER_NAME'].preg_replace('/&md=[^&=]+$/', '', $_SERVER['REQUEST_URI']);

  $match = strtoupper(md5($check.$uamsecret));

  if ($md == $match) return;

  echo "Error: bad url or uamsecret\n";
  exit;
}



// == database ==

/*

drop table networks;
create table networks (
  id serial,
  name varchar(200),
  uamsecret varchar(200),
  KEY(name),
  PRIMARY KEY(id)
);

drop table users;
create table users (
  id serial,
  network_id bigint unsigned,
  username varchar(200),
  password varchar(200),
  email varchar(200),

  -- "shared" attributes for acces control


  created datetime,
  FOREIGN KEY (network_id) REFERENCES networks(id),
  UNIQUE KEY (network_id, username),
  KEY(created),
  KEY(username),
  KEY(email),
  PRIMARY KEY(id)
);

drop table devices;
create table devices (
  id serial,
  network_id bigint unsigned,
  mac_address varchar(200),

  -- "shared" attributes for acces control

  FOREIGN KEY (network_id) REFERENCES networks(id),
  KEY(mac_address),
  PRIMARY KEY(id)
);

drop table codes;
create table codes (
  id serial,
  network_id bigint unsigned,
  device_id bigint unsigned,
  username varchar(200),
  password varchar(200),

  -- "shared" attributes for acces control
  access_disabled boolean default false,
  reply_message varchar(200),
  redirection_url varchar(200),
  authorized_until datetime,
  check_since datetime,
  idle_timeout integer unsigned,
  session_time integer unsigned,
  kbps_down integer unsigned,
  kbps_up integer unsigned,
  kbytes_total integer unsigned,
  kbytes_down integer unsigned,
  kbytes_up integer unsigned,

  created datetime,
  FOREIGN KEY (network_id) REFERENCES networks(id),
  FOREIGN KEY (device_id) REFERENCES devices(id),
  UNIQUE KEY (network_id, username),
  KEY(created),
  KEY(username),
  PRIMARY KEY(id)
);

drop table aps;
create table aps (
  id serial,
  network_id bigint unsigned,
  mac_address varchar(200),
  FOREIGN KEY (network_id) REFERENCES networks(id),
  KEY(mac_address),
  PRIMARY KEY(id)
);

drop table attributes;
create table attributes (
  key_id bigint unsigned not null,
  resource varchar(16) not null,
  name varchar(200) not null,
  value varchar(200),
  overwrite boolean default true,
  orderby integer default 0,
  KEY(orderby),
  KEY(key_id),
  KEY(resource),
  KEY(name)
);

drop table sessions;
create table sessions (
  id serial,
  ap_id bigint unsigned,
  network_id bigint unsigned,
  device_id bigint unsigned,
  user_id bigint unsigned,
  bytes_up bigint unsigned,      -- bytes uploaded by user
  bytes_down bigint unsigned,    -- bytes downloaded by user
  duration bigint unsigned,      -- duration in seconds
  auth_time datetime,            -- set to now() at authentication
  start_time datetime,           -- set to now() on accounting start
  update_time datetime,          -- set to now() on accounting start,update,stop
  stop_time datetime,            -- set to now() on accounting stop
  session_key varchar(200),      -- a unique key generated from session data
  FOREIGN KEY (ap_id) REFERENCES aps(id),
  FOREIGN KEY (network_id) REFERENCES networks(id),
  FOREIGN KEY (device_id) REFERENCES devices(id),
  FOREIGN KEY (user_id) REFERENCES users(id),
  KEY(session_key),
  KEY(bytes_up),
  KEY(bytes_down),
  KEY(duration),
  KEY(auth_time),
  KEY(start_time),
  KEY(update_time),
  KEY(stop_time),
  PRIMARY KEY(id)
);


*/

function db_open() {
  $dblink = mysql_connect('localhost', 'root', 'pico')
    or die('Could not connect: ' . mysql_error());

  mysql_select_db('http_aaa') 
    or die('Could not select database');

  return $dblink;
}

function db_query($query, $is_select = true) {
  global $dblink;
  $return = array();
  $result = mysql_query($query, $dblink) or die('Query failed: ' . mysql_error());
  if ($is_select && isset($result)) {
    while ($line = mysql_fetch_array($result, MYSQL_ASSOC)) $return[] = $line;
    mysql_free_result($result);
  }
  return $return;
}

function db_lastid() {
  global $dblink;
  return mysql_insert_id($dblink);
}

function db_close() {
  global $dblink;
  mysql_close($dblink);
}

function get_user() {
  global $hotspot_user;
  if ($hotspot_user) return $hotspot_user;
  $username = $_GET['user'];
  $network = get_network();
  $result = db_query('SELECT * FROM users WHERE username = \''.$username.'\' '.
		     'AND network_id = '.$network['id']);
  if (is_array($result)) return $hotspot_user = $result[0];
  return null;
}

function get_code() {
  global $hotspot_code;
  if ($hotspot_code) return $hotspot_code;
  $username = $_GET['user'];
  $network = get_network();
  $result = db_query('SELECT * FROM codes WHERE username = \''.$username.'\' '.
		     'AND network_id = '.$network['id']);
  if (is_array($result)) return $hotspot_code = $result[0];
  return null;
}

function get_device() {
  global $hotspot_device;
  if ($hotspot_device) return $hotspot_device;
  $mac = $_GET['mac'];
  if (!isset($mac) || $mac == '') return false;
  $network = get_network();
  $sql = 'SELECT * FROM devices WHERE mac_address = \''.$mac.'\' AND network_id = '.$network['id'];
  $result = db_query($sql);
  if (is_array($result) && is_array($result[0])) return $hotspot_device = $result[0];
  db_query('INSERT INTO devices (network_id, mac_address) VALUES ('.$network['id'].',\''.$mac.'\')', false);
  $result = db_query($sql);
  if (is_array($result)) return $hotspot_device = $result[0];
  return null;
}

function get_ap() {
  global $hotspot_ap;
  if ($hotspot_ap) return $hotspot_ap;
  $sql = 'SELECT * FROM aps WHERE mac_address = \''.$_GET['ap'].'\'';
  $result = db_query($sql);
  if (is_array($result)) $hotspot_ap = $result[0];
  return $hotspot_ap;
}

function get_network() {
  global $hotspot_ap;
  global $hotspot_network;
  if ($hotspot_network) return $hotspot_network;
  if (!$hotspot_ap) return false;
  $sql = 'SELECT * FROM networks WHERE id = \''.$hotspot_ap['network_id'].'\'';
  $result = db_query($sql);
  if (is_array($result)) return $hotspot_network = $result[0];
  return null;
}

function get_attributes($id, $tbl, &$array) {
  $sql = 'SELECT orderby, name, value, overwrite FROM attributes '.
    'WHERE key_id = \''.$id.'\' AND resource = \''.$tbl.'\' order by orderby';

  $result = db_query($sql);
  if (is_array($result)) {
    foreach ($result as $row) {
      if ($row['overwrite'] == 1 || !isset($array[$row['name']])) {
	$array[$row['name']] = $row['value'];
      }
    }
  }
}

function user_attributes(&$array, $user = false) {
  if (!$user) $user = get_user();
  obj_attributes($user, $array);
  get_attributes($user['id'], 'users', $array);
}

function code_attributes(&$array, $code = false) {
  if (!$code) $code = get_code();
  obj_attributes($code, $array);
  get_attributes($code['id'], 'codes', $array);
}

function network_attributes(&$array, $network = false) {
  if (!$network) $network = get_network();
  obj_attributes($network, $array);
  get_attributes($network['id'], 'networks', $array);
}

function ap_attributes(&$array, $ap = false) {
  if (!$ap) $ap = get_ap();
  obj_attributes($ap, $array);
  get_attributes($ap['id'], 'aps', $array);
}

function device_attributes(&$array, $device = false) {
  if (!$device) $device = get_device();
  obj_attributes($device, $array);
  get_attributes($device['id'], 'devices', $array);
}

function obj_attributes(&$obj, &$array) {

  $a = 
    array('reply_message' => 'set_reply_message',
	  'kbps_down' => 'set_max_bandwidth_down_kbit_sec',
	  'kbps_up' => 'set_max_bandwidth_up_kbit_sec',
	  );

  foreach ($a as $s => $f) {
    if (isset($obj[$s])) $f($array, $obj[$s]);
  }
}

function save_attributes($id, $tbl, &$array, $overwrite = 1) {
  $sql = 'DELETE FROM attributes WHERE key_id = \''.$id.'\' AND resource = \''.$tbl.'\'';
  db_query($sql, false);
  foreach ($array as $n => $v) {
    if ($n == '' || $v == '') continue;
    $sql = 'INSERT INTO attributes (key_id,resource,name,value,overwrite) '.
      'VALUES (\''.$id.'\',\''.$tbl.'\',\''.$n.'\',\''.$v.'\','.$overwrite.')';
    db_query($sql, false);
  }
}

function save_user_attributes(&$array, $user = false) {
  if (!$user) $user = get_user();
  return save_attributes($user['id'], 'users', $array);
}

function save_code_attributes(&$array, $user = false) {
  if (!$code) $code = get_code();
  return save_attributes($code['id'], 'codes', $array);
}

function save_network_attributes(&$array, $network = false) {
  if (!$network) $network = get_network();
  return save_attributes($network['id'], 'networks', $array);
}

function save_device_attributes(&$array, $device = false) {
  if (!$device) $device = get_device();
  return save_attributes($device['id'], 'devices', $array);
}

function save_ap_attributes(&$array, $ap = false) {
  if (!$ap) $ap = get_ap();
  return save_attributes($ap['id'], 'aps', $array);
}

function auth_session() {
  $network = get_network();
  $device = get_device();
  $user = get_user();
  $ap = get_ap();

  $s = date("Y-m-d H:i:s", time());

  $sql = 'INSERT INTO sessions (ap_id,network_id,device_id,user_id,auth_time,session_key) '.
    'VALUES ('.($ap ? $ap['id'] : 'null').','.
    ($network ? $network['id'] : 'null').','.
    ($device ? $device['id'] : 'null').','.
    ($user ? $user['id'] : 'null').','.
    '\''.$s.'\',\''.session_key().'\')';

  db_query($sql, false);
}

function start_session() {
  $s = date("Y-m-d H:i:s", time());

  $sql = 'UPDATE sessions SET start_time=\''.$s.'\',update_time=\''.$s.
    '\' WHERE session_key = \''.session_key().'\'';

  db_query($sql, false);
}

function _ses_update() {
  $result .= ',bytes_up='.$_GET['bytes_up'];
  $result .= ',bytes_down='.$_GET['bytes_down'];
  $result .= ',duration='.$_GET['duration'];
  return $result;
}

function stop_session() {
  $s = date("Y-m-d H:i:s", time());

  $sql = 'UPDATE sessions SET stop_time=\''.$s.'\',update_time=\''.$s.'\''._ses_update().
    ' WHERE session_key = \''.session_key().'\'';

  db_query($sql, false);
}

function update_session() {
  $s = date("Y-m-d H:i:s", time());

  $sql = 'UPDATE sessions SET update_time=\''.$s.'\''._ses_update().
    ' WHERE session_key = \''.session_key().'\'';

  db_query($sql, false);
}

function do_register() {
  $network = get_network();

  if ($_GET['status'] == 'new_code') {
    $sql = 'INSERT INTO codes (network_id, username, password, created) '.
      'VALUES ('.$network['id'].',\''.$_GET['user'].'\',\''.$_GET['pass'].'\', now())';
    $resource = 'codes';
  } else if ($_GET['status'] == 'new_user') {
    $sql = 'INSERT INTO users (network_id, username, password, created) '.
      'VALUES ('.$network['id'].',\''.$_GET['user'].'\',\''.$_GET['pass'].'\', now())';
    $resource = 'users';
  }

  db_query($sql, false);
  $id = db_lastid();

  if ($id) {
    $input = $_POST;

    if (!$input) 
      $input = file_get_contents("php://input");

    $lines = preg_split("/\n+/",$input);
    $attrs = array();

    foreach ($lines as $line) {
      $p = preg_split('/[=: ]+/', $line, 2);
      if ($p[0] && $p[1])
	$attrs[$p[0]] = $p[1];
    }

    save_attributes($id, $resource, $attrs);
  }
}

