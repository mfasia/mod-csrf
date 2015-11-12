mod_csrf.la: mod_csrf.slo
	$(SH_LINK) -rpath $(libexecdir) -module -avoid-version  mod_csrf.lo
DISTCLEAN_TARGETS = modules.mk
shared =  mod_csrf.la
