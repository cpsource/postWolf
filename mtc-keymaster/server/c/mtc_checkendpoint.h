/* mtc_checkendpoint.h — AbuseIPDB CHECK endpoint client */

#ifndef MTC_CHECKENDPOINT_H
#define MTC_CHECKENDPOINT_H

/* Initialize AbuseIPDB module. Reads API key and optionally connects to DB.
 * Returns 0 on success, -1 on failure, -2 if no API key found. */
int mtc_init(void);

/* Check an IP address against AbuseIPDB.
 * Returns abuseConfidenceScore (0-100) on success, <0 on failure.
 * -2 means no API key configured. */
int mtc_checkendpoint(char *ipaddr);

/* Set/get the abuse confidence score threshold for rejecting requests.
 * Default is 75.  Scores >= threshold cause rejection. */
void mtc_set_abuse_threshold(int threshold);
int  mtc_get_abuse_threshold(void);

#endif
