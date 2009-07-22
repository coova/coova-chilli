/* 
 *
 * Radius client functions.
 * Copyright (C) 2005 Mondru AB.
 * Copyright (C) 2007-2009 Coova Technologies, LLC. <support@coova.com>
 *
 * The contents of this file may be used under the terms of the GNU
 * General Public License Version 2, provided that the above copyright
 * notice and this permission notice is included in all copies or
 * substantial portions of the software.
 *
 */

#ifndef _RADIUS_CHILLISPOT_H
#define _RADIUS_CHILLISPOT_H

#define RADIUS_VENDOR_CHILLISPOT                      14559
#define	RADIUS_ATTR_CHILLISPOT_MAX_INPUT_OCTETS           1 /* integer */
#define	RADIUS_ATTR_CHILLISPOT_MAX_OUTPUT_OCTETS          2 /* integer */
#define	RADIUS_ATTR_CHILLISPOT_MAX_TOTAL_OCTETS           3 /* integer */
#define	RADIUS_ATTR_CHILLISPOT_BANDWIDTH_MAX_UP	          4 /* integer */
#define	RADIUS_ATTR_CHILLISPOT_BANDWIDTH_MAX_DOWN         5 /* integer */
#define	RADIUS_ATTR_CHILLISPOT_CONFIG                     6 /* string */
#define RADIUS_ATTR_CHILLISPOT_LANG                       7 /* string */
#define RADIUS_ATTR_CHILLISPOT_VERSION                    8 /* string */
#define RADIUS_ATTR_CHILLISPOT_ORIGINALURL                9 /* string */
#define RADIUS_ATTR_CHILLISPOT_ACCT_VIEW_POINT           10 /* integer */
#define RADIUS_ATTR_CHILLISPOT_REQUIRE_UAM               11 /* integer */
#define RADIUS_ATTR_CHILLISPOT_REQUIRE_SPLASH            12 /* integer */
#define RADIUS_ATTR_CHILLISPOT_ROUTE_TO_INTERFACE        13 /* integer */
#define	RADIUS_ATTR_CHILLISPOT_MAX_INPUT_GIGAWORDS       21 /* integer */
#define	RADIUS_ATTR_CHILLISPOT_MAX_OUTPUT_GIGAWORDS      22 /* integer */
#define	RADIUS_ATTR_CHILLISPOT_MAX_TOTAL_GIGAWORDS       23 /* integer */
#define	RADIUS_ATTR_CHILLISPOT_VLAN_ID                   24 /* integer */

#define RADIUS_ATTR_CHILLISPOT_SYS_UPTIME                40 /* integer */
#define RADIUS_ATTR_CHILLISPOT_SYS_LOADAVG               41 /* string */
#define RADIUS_ATTR_CHILLISPOT_SYS_MEMORY                42 /* string */

#define RADIUS_ATTR_CHILLISPOT_DHCP_VENDOR_CLASS_ID      50 /* string */
#define RADIUS_ATTR_CHILLISPOT_DHCP_CLIENT_ID            51 /* string */
#define RADIUS_ATTR_CHILLISPOT_DHCP_OPTION               52 /* string */
#define RADIUS_ATTR_CHILLISPOT_DHCP_FILENAME             53 /* string */
#define RADIUS_ATTR_CHILLISPOT_DHCP_HOSTNAME             54 /* string */
#define RADIUS_ATTR_CHILLISPOT_DHCP_SERVER_NAME          55 /* string */
#define RADIUS_ATTR_CHILLISPOT_DHCP_CLIENT_FQDN          56 /* string */
#define RADIUS_ATTR_CHILLISPOT_DHCP_PARAMETER_REQUEST_LIST 57 /* string */

#define RADIUS_VALUE_CHILLISPOT_NAS_VIEWPOINT             1
#define RADIUS_VALUE_CHILLISPOT_CLIENT_VIEWPOINT          2

#endif	/* !_RADIUS_CHILLISPOT_H */
