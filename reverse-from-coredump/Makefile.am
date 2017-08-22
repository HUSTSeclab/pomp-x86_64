SUBDIRS=src
dist_doc_DATA=README

TESTSUITES_DIR = testsuites
EXECUTABLE=$(SUBDIRS)/reverse

latex2rtf:
	$(EXECUTABLE) $(TESTSUITES_DIR)/$@/core $(TESTSUITES_DIR)/$@/libs/ $(TESTSUITES_DIR)/$@/inst.reverse $(TESTSUITES_DIR)/$@/reginfo.reverse $(TESTSUITES_DIR)/$@/xmm.log $(TESTSUITES_DIR)/$@/summary.lib
