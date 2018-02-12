PROG=segvan
CSTD=c99
BINDIR=/usr/local/bin
MANDIR=/usr/local/man/man

INSTALLFLAGS+=-S

OBJS+=segwit_addr.o #\
#	secp256k1/.libs/libsecp256k1.a

all: secp256k1/.libs/libsecp256k1.a

.if ("$(.CURDIR)" == "$(.OBJDIR)")
SECDIR=$(.CURDIR)/secp256k1
secdir: .PHONY
	:
.else
SECDIR=$(.OBJDIR)/secp256k1
secdir: .PHONY
	# Always leery of these in makefiles:
	# rm -rf "$(SECDIR)"
	if [ ! -f $(.OBJDIR)/secp256k1/.libs/libsecp256k1.a ] ; then \
		(cd $(.OBJDIR) && rm -rf secp256k1) ; \
		cp -Rp $(.CURDIR)/secp256k1 $(.OBJDIR) ; \
		test -d $(SECDIR) ; \
	fi
.endif

secp256k1/.libs/libsecp256k1.a: secdir
	if [ ! -f $@ ] ; then \
		test -d `dirname $@` || mkdir -p `dirname $@` ; \
		rm -f $@ ; \
		(cd $(SECDIR) && ./configure --enable-static --disable-shared) ; \
		gmake -C $(SECDIR) ; \
		if [ ! -f $@ ] ; then \
			cp -a $(.CURDIR)/.libs/* `dirname $@` ; \
		fi ; \
	fi
	test -f $@

LDADD=-lcrypto -lsecp256k1
LDFLAGS=-L$(.OBJDIR)/secp256k1/.libs

.include <bsd.prog.mk>
