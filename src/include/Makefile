#
# Makefile
#
# Version:	$Id$
#

HEADERS	= autoconf.h conf.h conffile.h detail.h dhcp.h event.h hash.h heap.h \
	ident.h libradius.h md4.h md5.h missing.h modcall.h modules.h \
	packet.h rad_assert.h radius.h radiusd.h radpaths.h \
	radutmp.h realms.h sha1.h stats.h sysutmp.h threads.h token.h \
	udpfromto.h vmps.h vqp.h base64.h \
	portnox/dep/credis.h portnox/dep/cJSON.h \
	portnox/redis_client.h portnox/redis_dal.h \
	portnox/curl_client.h portnox/dstr.h portnox/portnox_config.h \
	portnox/portnox_auth.h portnox/string_helper.h portnox/attrs_helper.h \
	portnox/portnox_common.h portnox/log_helper.h

include ../../Make.inc
.PHONY: all clean distclean install

.PHONY: all clean distclean install reconfig
all: radpaths.h

radpaths.h: build-radpaths-h
	@/bin/sh ./build-radpaths-h

distclean:
	rm -f radpaths.h

reconfig clean:

install:
	$(INSTALL) -d -m 755 $(R)$(includedir)/freeradius
	for i in $(HEADERS); do \
		sed 's/^#include <freeradius-devel/#include <freeradius/' $$i > .inst.$$$$ ; \
		$(INSTALL) -m 644 .inst.$$$$   $(R)$(includedir)/freeradius/$$i; \
		rm -f .inst.$$$$ ; \
	done
