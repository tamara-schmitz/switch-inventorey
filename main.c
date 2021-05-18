#include <stdlib.h> 
#include <stdio.h>
#include <unistd.h> 
#include <stdbool.h>
#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>

void create_session_v12(struct snmp_session * session, const char *peername, const char *community, const int version);
int create_session_v3(struct snmp_session * session, const char *peername, const char *sec_name, const char *passphrase, oid *sec_authproto);
int walk_oid(const char *str_oid, struct snmp_session * session, struct snmp_pdu * response_pdu, oid ** oNext, size_t * oNext_len);
void create_pdu_getrequest(const char *str_oid, struct snmp_pdu ** pdu);
int do_request(struct snmp_session * session, struct snmp_pdu * request_pdu, struct snmp_pdu * response_pdu);

int main(int argc, char *argv[], char *envp[]) {
	struct snmp_session session_initial;
	// results
	struct snmp_session *ss;
	struct snmp_pdu *pdu_send = NULL, *pdu_send2 = NULL, *pdu_send3 = NULL;
	struct snmp_pdu *pdu_response = NULL;
	int ss_status;
	oid ss_oid[MAX_OID_LEN];
	size_t ss_oid_len = MAX_OID_LEN;

	struct variable_list *vars;

	// TODO while getopt to parse arguments if i ever want to

	init_snmp("snmpapp");

	// create_session_v3(&session_initial, "192.168.100.172", "someuser", "The Net-SNMP Demo Password", usmHMACMD5AuthProtocol);
	//create_session_v1(&session_initial, "192.168.100.172", "public");
	create_session_v12(&session_initial, "10.161.56.25", "public", SNMP_VERSION_2c);

	// Start Session
	ss = snmp_open(&session_initial);
	if (!ss) {
		snmp_perror("Session could not be started");
		snmp_log(LOG_ERR, "Unable to start session.\n");
		exit(2);
	}

	// Host info
	create_pdu_getrequest(".1.3.6.1.2.1.1.1", &pdu_send);
	do_request(ss, pdu_send, pdu_response);
	if (pdu_response)
		snmp_free_pdu(pdu_response);

	// Host uptime
	create_pdu_getrequest(".1.3.6.1.2.1.1.3", &pdu_send);
	do_request(ss, pdu_send, pdu_response);
	if (pdu_response)
		snmp_free_pdu(pdu_response);

	// -- Mellanox queries
	// switch's MAC
	walk_oid("1.3.6.1.2.1.17.1.1", ss, pdu_response, NULL, NULL);

	// MAC table
	create_pdu_getrequest("1.3.6.1.2.1.17.7.1.2.2", &pdu_send);
	do_request(ss, pdu_send, pdu_response);
	if (pdu_response)
		snmp_free_pdu(pdu_response);

	// VLAN names
	create_pdu_getrequest("1.3.6.1.2.1.17.7.1.4.3.1.1", &pdu_send);
	do_request(ss, pdu_send, pdu_response);
	if (pdu_response)
		snmp_free_pdu(pdu_response);

	// ifAlias
	create_pdu_getrequest("1.3.6.1.2.1.31.1.1.1.18", &pdu_send);
	do_request(ss, pdu_send, pdu_response);
	if (pdu_response)
		snmp_free_pdu(pdu_response);

	// LLDP
	create_pdu_getrequest("1.0.8802.1.1.2.1.4.1.1.9", &pdu_send);
	do_request(ss, pdu_send, pdu_response);
	if (pdu_response)
		snmp_free_pdu(pdu_response);


	// Cleanup
	snmp_close(ss); // or use snmp_close_sessions();

	return 0;
}

void create_session_v12(struct snmp_session * session, const char *peername, const char *community, const int version) {
	snmp_sess_init(session);
	session->peername = strdup(peername);

	session->version = version;
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

int walk_oid(const char *str_oid, struct snmp_session * session, struct snmp_pdu * response_pdu, oid ** oNext, size_t * oNext_len) {
	// either interprets str_oid and returns response along with next OID in subtree if applicable.
	// or if next OID is given, next OID processed instead if subtree of str_oid
	// returns not null if a next oid exists.
	struct snmp_pdu *pdu_request;
	oid ss_oid[MAX_OID_LEN];
	size_t ss_oid_len = MAX_OID_LEN;

	read_objid(str_oid, ss_oid, &ss_oid_len); // interpret oid from string

	// return if oNext is not a common prefix to str_oid
	if (*oNext && netsnmp_oid_find_prefix(ss_oid, ss_oid_len, *oNext, *oNext_len) <= 0)
		return 0;

	pdu_request = snmp_pdu_create(SNMP_MSG_GETNEXT);
	if (oNext) {
		if (!snmp_add_null_var(pdu_request, *oNext, *oNext_len)) // add a varbind with OID only 
			snmp_log(LOG_ERR, "Appending next varbind to PDU during walk has failed\n");
	} else {
		if (!snmp_add_null_var(pdu_request, ss_oid, ss_oid_len)) // add a varbind with OID only 
			snmp_log(LOG_ERR, "Appending varbind to PDU during walk has failed\n");

	}
	do_request(session, pdu_request, response_pdu);

	// return if response
	if (!netsnmp_oid_equals(ss_oid, ss_oid_len, *oNext, *oNext_len)) {
		return 0;
	}

	if (netsnmp_oid_equals(response_pdu->variables->name, response_pdu->variables->name_length, *oNext, *oNext_len)) {
		//if (oNext)
		//free(oNext);
		oNext = snmp_duplicate_objid(response_pdu->variables->name, response_pdu->variables->name_length);
		oNext_len = response_pdu->variables->name_length;

		return 1;
	}

	return 0;
}

void create_pdu_getrequest(const char *str_oid, struct snmp_pdu ** pdu) {
	oid ss_oid[MAX_OID_LEN];
	size_t ss_oid_len = MAX_OID_LEN;
	read_objid(str_oid, ss_oid, &ss_oid_len); // interpret oid from string

	// Prepare a PDU for request
	*pdu = snmp_pdu_create(SNMP_MSG_GET);

	if (!snmp_add_null_var(*pdu, ss_oid, ss_oid_len)) // add a varbind with OID only 
		snmp_log(LOG_ERR, "Appending varbind to PDU failed\n");
}

int do_request(struct snmp_session * session, struct snmp_pdu * request_pdu, struct snmp_pdu * response_pdu) {
	int ss_status;

	// Send Request and Read Response
	ss_status = snmp_synch_response(session, request_pdu, &response_pdu);

	if (ss_status == STAT_SUCCESS && response_pdu->errstat == SNMP_ERR_NOERROR) {
		// SUCCESS
		// TODO make this NOP
		for (netsnmp_variable_list *vars = response_pdu->variables; vars; 
				vars = vars->next_variable)
			print_variable(vars->name, vars->name_length, vars);

		return ss_status;
	}
	else {
		// FAILURE
		if (ss_status == STAT_SUCCESS) {
			fprintf(stderr, "Error in request packet:\n%s\n",
					snmp_errstring(response_pdu->errstat));
			return response_pdu->errstat;
		}
		else {
			snmp_sess_perror("snmpget", session);
			return ss_status;
		}
	}

}
