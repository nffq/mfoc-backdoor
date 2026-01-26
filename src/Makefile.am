AM_CFLAGS  = @libnfc_CFLAGS@

bin_PROGRAMS = mfoc-backdoor

noinst_HEADERS = crapto1.h mfoc.h mifare.h nfc-utils.h staticnested.h

mfoc_backdoor_SOURCES = crapto1.c crypto1.c mfoc.c mifare.c nfc-utils.c staticnested.c
mfoc_backdoor_LDADD   = @libnfc_LIBS@

dist_man_MANS = mfoc.1
