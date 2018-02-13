PROG=segvan
CSTD=c99
BINDIR=/usr/local/bin
#MANDIR=/usr/local/man/man
NO_MAN=

INSTALLFLAGS+=-S

OBJS+=segwit_addr.o #\
#	secp256k1/.libs/libsecp256k1.a

all: secp256k1/.libs/libsecp256k1.a

#
# The find/touch line is caused by autoconf problems.  After hours of pain,
# a vague hint to the solution was found in the fine print (comments) at:
# https://stackoverflow.com/questions/24233721/build-m4-autoconf-automake-libtool-on-unix
#

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
		(cd $(SECDIR) && find * -type f -print0 | xargs -0 touch -d 1970-01-01T00:00:00Z) ; \
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
