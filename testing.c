// CFLAGS="-std=c99 -fPIE -fstack-protector-all -D_FORTIFY_SOURCE=2 -march=nehalem" 
// LDFLAGS="-lnetsnmp -Wall -Wextra"
//// LDFLAGS="-Wl,-z,now -Wl,-z,relro"
// gcc $CFLAGS $LDFLAGS -o switch-monitor main.c

#include <stdlib.h> 
#include <stdio.h>
#include <unistd.h> 
#include <stdbool.h>
#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>

int main(int argc, char* argv[], char* envp[])
{
	struct snmp_session session_initial;
	// results
	struct snmp_session *ss;
	struct snmp_pdu *pdu_send, *pdu_response;
	int ss_status;
	oid ss_oid[MAX_OID_LEN];
	size_t ss_oid_len = MAX_OID_LEN;

	struct variable_list *vars;

	// TODO while getopt to parse arguments if i ever want to

	init_snmp("snmpapp");

	// define hardcoded session info
	snmp_sess_init(&session_initial);
	session_initial.peername = "192.168.100.172";

	bool useV3 = false;

	if (useV3)
	{
		const char *ssv3_passphrase = "The Net-SNMP Demo Password";
		session_initial.version = SNMP_VERSION_3;
		session_initial.securityName = strdup("someuser");
		session_initial.securityNameLen = strlen(session_initial.securityName);
		/* set the security level to authenticated, but not encrypted */
		session_initial.securityLevel = SNMP_SEC_LEVEL_AUTHNOPRIV;
		/* set the authentication method to MD5 */
		session_initial.securityAuthProto = usmHMACMD5AuthProtocol;
		session_initial.securityAuthProtoLen = sizeof(usmHMACMD5AuthProtocol)/sizeof(oid);
		session_initial.securityAuthKeyLen = USM_AUTH_KU_LEN;
		/* set the authentication key to a MD5 hashed version of our
		   passphrase "The Net-SNMP Demo Password" (which must be at least 8
		   characters long) */
		if (generate_Ku(session_initial.securityAuthProto,
					session_initial.securityAuthProtoLen,
					(u_char *) ssv3_passphrase, strlen(ssv3_passphrase),
					session_initial.securityAuthKey,
					&session_initial.securityAuthKeyLen) != SNMPERR_SUCCESS) {
			snmp_perror(argv[0]);
			snmp_log(LOG_ERR,
					"Error generating Ku from authentication pass phrase. \n");
			exit(1);
		}
	}
	else
	{
		// SNMPv1 implementation
		session_initial.version = SNMP_VERSION_1;
		session_initial.community = "public";
		session_initial.community_len = strlen(session_initial.community);
	}

	// Start Session
	ss = snmp_open(&session_initial);
	if (!ss) {
		snmp_perror("Session could not be started");
		snmp_log(LOG_ERR, "Unable to start session.\n");
		exit(2);
	}

	// Prepare PDU for request
	pdu_send = snmp_pdu_create(SNMP_MSG_GET);
	read_objid(".1.3.6.1.2.1.1.1.0", ss_oid, &ss_oid_len);
	snmp_add_null_var(pdu_send, ss_oid, ss_oid_len); // the oid's val is null in a request

	// Send Request
	ss_status = snmp_synch_response(ss, pdu_send, &pdu_response);

	// Process status
	if (ss_status == STAT_SUCCESS && pdu_response->errstat == SNMP_ERR_NOERROR)
	{
		// SUCESS
		for (vars = pdu_response->variables; vars; vars = vars->next_variable)
			print_variable(vars->name, vars->name_length, vars);
	}
	else
	{
		// FAILURE
		if (ss_status == STAT_SUCCESS)
			fprintf(stderr, "Error in request packet:\n%s\n",
					snmp_errstring(pdu_response->errstat));
		else
			snmp_sess_perror("snmpget", ss);
	}

	// Cleanup
	if (pdu_response)
		snmp_free_pdu(pdu_response);
	snmp_close(ss);

	return 0;
}
