#include <stdlib.h>
#include <unistd.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sqlite3.h>

int main(int argc, char *argv[], char *envp[]) {
	sqlite3 *db_conn;
	int status;

	// Open DB
	status = sqlite3_open("test-db.db", &db_conn);

	if (status) {
		fprintf(stderr, "Can't open database: %d %s\n", status, sqlite3_errmsg(db_conn));
		return(1);
	}
	fprintf(stderr, "Opened database successfully\n");

	// Create Tables from .sql
	char * sql_text = NULL;
	size_t sql_text_size;
	char * errmsgs;
	FILE * fh_sql = fopen("create-tables.sql", "r");
	if (!fh_sql && fread(sql_text, sizeof(char), 1048576, fh_sql) <= 0)
		fprintf(stderr, "Could not open or read SQL file for DB table creation!");
	fclose(fh_sql);

	status = sqlite3_exec(db_conn, sql_text, NULL, NULL, &errmsgs);
	if (status != SQLITE_OK) {
		fprintf(stderr, "Can't execute query: %d %s %s\n", status, errmsgs, sqlite3_errmsg(db_conn));
		return(1);
	}
	printf("Tables created...\n");

	// Prepare SELECT query
	sqlite3_stmt *sql_statement;
	sql_text = "SELECT * FROM DeviceLog, Switches;";
	status = sqlite3_prepare_v3(db_conn, sql_text, -1,
			0, &sql_statement, NULL);
	if (status) {
		fprintf(stderr, "Can't prepare statement: %d %s\n", status, sqlite3_errmsg(db_conn));
		return(1);
	}

	// Step through query
	status = SQLITE_ROW;
	while (status == SQLITE_ROW) {
		status = sqlite3_step(sql_statement);
		printf("SQLITE_CODE: %d\n", status);
		if (status != SQLITE_ROW && status != SQLITE_DONE && status != SQLITE_OK) {
			fprintf(stderr, "Can't step through statement: %d %s\n", status, sqlite3_errmsg(db_conn));
			// clean up and stop
			return(1);
		}

		// Process Row result
		if (status == SQLITE_ROW) {
			int cols = sqlite3_column_count(sql_statement);
			for (int i = 0; i < cols; i++) {
				int type = sqlite3_column_type(sql_statement, i);
				// char *name = 
				switch (type) {
					case SQLITE_INTEGER: {
								     printf("Int: %d\n", sqlite3_column_int(sql_statement, i));
								     break;
							     }
					case SQLITE_FLOAT:
					case SQLITE3_TEXT: {
								   const void *ptr_txt = sqlite3_column_text(sql_statement, i);
								   size_t size_txt = sqlite3_column_bytes(sql_statement, i);

								   // copy text. and we need to add a null terminator
								   char* text = malloc(size_txt+1);
								   text[size_txt] = '\0';
								   memcpy(text, ptr_txt, size_txt);
								   printf("Text: %s \n", text);
								   printf("size_txt == strlen(text): %i\n", size_txt == strlen(text));
								   free(text);
								   break;
							   }
					case SQLITE_BLOB: {
								  const void *ptr_blob = sqlite3_column_blob(sql_statement, i);
								  int size_blob = sqlite3_column_bytes(sql_statement, i);
								  void* blob = malloc(size_blob);
								  memcpy(blob, ptr_blob, size_blob);
								  printf("Text: %s\n", (char *) blob);
								  free(blob);
								  break;
							  }
					case SQLITE_NULL: {
								  printf("Null\n");
								  break;
							  }
					default:
							  printf("Warning: Unknown SQLITE data type in column %d\n", i);
				}
			}

		}
	}

	sqlite3_finalize(sql_statement);
	sqlite3_close(db_conn);
	return 0;
}
