#include <stdlib.h> 
#include <stdio.h>
#include <unistd.h> 
#include <stdbool.h>
#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>

void create_session_v1(struct snmp_session * session, const char *peername, const char *community);
int create_session_v3(struct snmp_session * session, const char *peername, const char *sec_name, const char *passphrase, oid *sec_authproto);
void create_pdu_getrequest(const char *s_oid, struct snmp_pdu * pdu);
int do_request(struct snmp_session * session, struct snmp_pdu * request_pdu, struct snmp_pdu * response_pdu);

int main(int argc, char *argv[], char *envp[]) {
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

	// create_session_v3(&session_initial, "192.168.100.172", "someuser", "The Net-SNMP Demo Password", usmHMACMD5AuthProtocol);
	create_session_v1(&session_initial, "192.168.100.172", "public");

	// Start Session
	ss = snmp_open(&session_initial);
	if (!ss) {
		snmp_perror("Session could not be started");
		snmp_log(LOG_ERR, "Unable to start session.\n");
		exit(2);
	}

	// Prepare PDU for request
	create_pdu_getrequest(".1.3.6.1.2.1.1.1.0", pdu_send);

	do_request(ss, pdu_send, pdu_response);

	// Cleanup
	if (pdu_response)
		snmp_free_pdu(pdu_response);
	snmp_close(ss);

	return 0;
}

void create_session_v1(struct snmp_session * session, const char *peername, const char *community) {
	snmp_sess_init(session);
	session->peername = strdup(peername);

	session->version = SNMP_VERSION_1;
	session->community = (u_char *) strdup(community);
	session->community_len = strlen(community);
}

int create_session_v3(struct snmp_session * session, const char *peername, const char *sec_name, const char *passphrase, oid *sec_authproto) {
	int status;
	const char *pass = strdup(passphrase);

	snmp_sess_init(session);
	session->peername = strdup(peername);

	session->version = SNMP_VERSION_3;
	session->securityName = strdup(sec_name);
	session->securityNameLen = strlen(sec_name);
	session->securityLevel = SNMP_SEC_LEVEL_AUTHNOPRIV;
	session->securityAuthProto = sec_authproto;
	session->securityAuthProtoLen = sizeof(*(session->securityAuthProto))/MAX_OID_LEN;
	session->securityAuthKeyLen = USM_AUTH_KU_LEN;

	status = generate_Ku(session->securityAuthProto,
			session->securityAuthProtoLen,
			(u_char *) pass, strlen(pass),
			session->securityAuthKey,
			&session->securityAuthKeyLen);

	if (status != SNMPERR_SUCCESS) {
		snmp_log(LOG_ERR,
				"Error generating Ku from authentication pass phrase. \n");
	}

	return status;

}

void create_pdu_getrequest(const char *s_oid, struct snmp_pdu * pdu) {
	oid ss_oid[MAX_OID_LEN];
	size_t ss_oid_len = MAX_OID_LEN;

	// Prepare PDU for request
	pdu = snmp_pdu_create(SNMP_MSG_GET);
	read_objid(s_oid, ss_oid, &ss_oid_len);
	snmp_add_null_var(pdu, ss_oid, ss_oid_len); // the oid's val is null in a request
}

int do_request(struct snmp_session * session, struct snmp_pdu * request_pdu, struct snmp_pdu * response_pdu) {
	int ss_status;

	// Send Request
	ss_status = snmp_synch_response(session, request_pdu, &response_pdu);

	if (ss_status == STAT_SUCCESS && response_pdu->errstat == SNMP_ERR_NOERROR) {
		// SUCESS
		// TODO make this NOP
		for (netsnmp_variable_list *vars = response_pdu->variables; vars; vars = vars->next_variable)
			print_variable(vars->name, vars->name_length, vars);
	}
	else {
		// FAILURE
		if (ss_status == STAT_SUCCESS)
			fprintf(stderr, "Error in request packet:\n%s\n",
					snmp_errstring(response_pdu->errstat));
		else
			snmp_sess_perror("snmpget", session);
	}

	return ss_status;
}
