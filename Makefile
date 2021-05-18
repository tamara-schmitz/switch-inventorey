CFLAGS     = -fPIE -fstack-protector-strong
CFLAGS_REL = -O3 -D_FORTIFY_SOURCE=2
CFLAGS_DEV = -g
LIBS       = -lnetsnmp -lsqlite3
LDFLAGS    = -Wall -Wno-unused-variable
OUT        = out

switch_monitor: main.c
	@mkdir -p $(OUT)
	$(CC) $(CFLAGS) $(CFLAGS_DEV) $? $(LDFLAGS) $(LIBS) -o $(OUT)/$@
	#$(CC) $(CFLAGS) $(CFLAGS_DEV) $? $(LDFLAGS) $(LIBS) -c
	
preprocessed: main.c
	@mkdir -p $(OUT)
	$(CC) $(CFLAGS) -E $(CFLAGS_DEV) $? $(LDFLAGS) $(LIBS) -o $(OUT)/$@.c

assembly: main.c
	$(CC) $(CFLAGS) $(CFLAGS_DEV) -fverbose-asm $? $(LDFLAGS) $(LIBS) -S -o $(OUT)/$@_debug.s
	$(CC) $(CFLAGS) $(CFLAGS_REL) -fverbose-asm $? $(LDFLAGS) $(LIBS) -S -o $(OUT)/$@_release.s 

release: main.c
	@mkdir -p $(OUT)
	$(CC) $(CFLAGS) $(CFLAGS_REL) $? $(LDFLAGS) $(LIBS) -o $(OUT)/$@

test-sqlite: test-sqlite.c
	@mkdir -p $(OUT)
	$(CC) $(CFLAGS) $(CFLAGS_DEV) $? $(LDFLAGS) $(LIBS) -o $(OUT)/$@
