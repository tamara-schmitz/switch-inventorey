#include <stdlib.h> 
#include <stdio.h>
#include <unistd.h> 
#include <stdbool.h>
#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>

void create_session_v12(struct snmp_session *session, const char *peername, const char *community, const int version);
int create_session_v3(struct snmp_session *session, const char *peername, const char *sec_name, const char *passphrase, oid *sec_authproto);
int walk_oid(struct snmp_session *session, const char *str_oid, const oid * prev_oid, const size_t prev_oid_size, struct snmp_pdu *response_pdu);
void create_pdu_getrequest(const char *str_oid, struct snmp_pdu **pdu);
int do_request(struct snmp_session *session, struct snmp_pdu *request_pdu, struct snmp_pdu *response_pdu);

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
	walk_oid(ss, "1.3.6.1.2.1.17.1.1", NULL, 0, pdu_response);

	// MAC table
	//create_pdu_getrequest("1.3.6.1.2.1.17.7.1.2.2", &pdu_send);
	//do_request(ss, pdu_send, pdu_response);
	oid *prevOID = NULL;
	size_t prevOID_size = 0;
	while (walk_oid(ss, "1.3.6.1.2.1.17.7.1.2.2", prevOID, prevOID_size, pdu_response) == 0) {
		printf("A while loop iteration...");
		for (netsnmp_variable_list *vars = pdu_response->variables; vars; 
				vars = vars->next_variable) {
			print_variable(vars->name, vars->name_length, vars);
			prevOID = snmp_duplicate_objid(vars->name, vars->name_length);
			prevOID_size = vars->name_length;
		}
	}
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

void create_session_v12(struct snmp_session *session, const char *peername, const char *community, const int version) {
	snmp_sess_init(session);
	session->peername = strdup(peername);

	session->version = version;
	session->community = (u_char *) strdup(community);
	session->community_len = strlen(community);
}

int create_session_v3(struct snmp_session *session, const char *peername, const char *sec_name, const char *passphrase, oid *sec_authproto) {
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

// rewrite
int walk_oid(struct snmp_session *session, const char *str_oid, const oid * prev_oid, const size_t prev_oid_size, struct snmp_pdu *response_pdu) {
	// returns 0 if a next oid exists.
	// returns >0 if no next oid exists. response_pdu may or may not be null
	// returns <0 on error
	oid parent_oid[MAX_OID_LEN];
	size_t parent_oid_size = MAX_OID_LEN;
	struct snmp_pdu *request_pdu;
	if (response_pdu)
		snmp_free_pdu(response_pdu);
	response_pdu = NULL;

	read_objid(str_oid, parent_oid, &parent_oid_size);

	if (!prev_oid) {
		// query the parent
		request_pdu = snmp_pdu_create(SNMP_MSG_GET);
		if (!snmp_add_null_var(request_pdu, parent_oid, parent_oid_size)) { // add a varbind with OID only 
			snmp_log(LOG_ERR, "Appending next varbind to PDU during walk has failed\n");
			return -1;
		}

		if (do_request(session, request_pdu, response_pdu) != STAT_SUCCESS)
			return -1;

		return 0;
	} else {
		// query next obj
		request_pdu = snmp_pdu_create(SNMP_MSG_GETNEXT);
		if (!snmp_add_null_var(request_pdu, prev_oid, prev_oid_size)) { // add a varbind with OID only 
			snmp_log(LOG_ERR, "Appending next varbind to PDU during walk has failed\n");
			return -1;
		}

		if (do_request(session, request_pdu, response_pdu) != STAT_SUCCESS)
			return -1;

		netsnmp_variable_list *vars = response_pdu->variables;
		if (vars && vars->name && vars->name_length && 
				netsnmp_oid_equals(prev_oid, prev_oid_size, vars->name, vars->name_length) &&
				netsnmp_oid_is_subtree(parent_oid, parent_oid_size, vars->name, vars->name_length) == 0) {
			return 0;
		} else {
			return 1; // end of the list tree
		}
	}

}

void create_pdu_getrequest(const char *str_oid, struct snmp_pdu **pdu) {
	oid ss_oid[MAX_OID_LEN];
	size_t ss_oid_len = MAX_OID_LEN;
	read_objid(str_oid, ss_oid, &ss_oid_len); // interpret oid from string

	// Prepare a PDU for request
	*pdu = snmp_pdu_create(SNMP_MSG_GET);

	if (!snmp_add_null_var(*pdu, ss_oid, ss_oid_len)) // add a varbind with OID only 
		snmp_log(LOG_ERR, "Appending varbind to PDU failed\n");
}

int do_request(struct snmp_session *session, struct snmp_pdu *request_pdu, struct snmp_pdu *response_pdu) {
	int ss_status;
	if (response_pdu)
		snmp_free_pdu(response_pdu);
	response_pdu = NULL;

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
