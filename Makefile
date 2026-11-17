PREFIX?= /usr/local
SHARE= ${PREFIX}/share/gatebsd
ETCDIR= ${PREFIX}/etc/gatebsd
RCDIR= ${PREFIX}/etc/rc.d
SBINDIR= ${PREFIX}/sbin
VARDB= /var/db/gatebsd
VARDB_SYSTEM= /var/db/gatebsd-system
VARRUN= /var/run/gatebsd
# The lua loader reads /boot/loader.conf.d/*.conf. Overridable so the delivery
# can be exercised into a staging directory without touching a real /boot.
BOOTCONFDIR?= /boot/loader.conf.d
SSHDCONFDIR?= /etc/ssh/sshd_config.d
VERSION!= cat VERSION
PYTHON?= python3
.PHONY: all install install-safe install-loader-conf uninstall check clean source-archive source-manifest
all:
	@echo "GateBSD ${VERSION}: install-safe check uninstall"
install: install-safe
	@echo "Safe installation completed. Run gatebsd-install for discovery and backup."
install-safe:
	@set -eu; for d in ${PREFIX} ${SHARE} ${SHARE}/webui ${SHARE}/webui/backend ${SHARE}/webui/frontend ${SHARE}/etc ${RCDIR} ${SBINDIR} ${PREFIX}/libexec ${PREFIX}/etc/cron.d ${PREFIX}/etc/newsyslog.conf.d; do \
	  [ ! -L "$$d" ] && { [ ! -e "$$d" ] || [ -d "$$d" ]; } || { echo "Unsafe install directory: $$d" >&2; exit 1; }; \
	done
	install -d ${SHARE}/webui/backend ${SHARE}/webui/frontend ${SHARE}/etc/gatebsd ${SHARE}/etc/nginx ${SHARE}/etc/unbound ${SHARE}/etc/amnezia ${SHARE}/etc/nut ${SHARE}/etc/pkg/repos ${SHARE}/etc/pkg/keys ${RCDIR} ${SBINDIR} ${PREFIX}/libexec ${PREFIX}/etc/cron.d ${PREFIX}/etc/newsyslog.conf.d
	rm -rf ${SHARE}/webui/backend/gatebsd_ui
	cp -R webui/backend/gatebsd_ui ${SHARE}/webui/backend/
	find ${SHARE}/webui/backend/gatebsd_ui -name '*.pyc' -delete
	find ${SHARE}/webui/backend/gatebsd_ui -name __pycache__ -type d -exec rm -rf {} + 2>/dev/null || true
	cp webui/frontend/*.html webui/frontend/*.js webui/frontend/*.css ${SHARE}/webui/frontend/
	scripts/stamp-frontend-version.sh ${SHARE}/webui/frontend
	install -m 644 VERSION ${SHARE}/VERSION
	install -m 640 etc/gatebsd.conf ${SHARE}/etc/gatebsd.conf.sample
	install -m 600 etc/gatebsd/failover.conf.sample ${SHARE}/etc/gatebsd/failover.conf.sample
	install -m 600 etc/gatebsd/duckdns.conf.sample ${SHARE}/etc/gatebsd/duckdns.conf.sample
	install -m 644 etc/gatebsd/repo-sources.conf.sample ${SHARE}/etc/gatebsd/repo-sources.conf.sample
	install -m 600 etc/gatebsd/split-dns.conf.sample ${SHARE}/etc/gatebsd/split-dns.conf.sample
	install -m 644 etc/nginx/gatebsd.conf.sample ${SHARE}/etc/nginx/gatebsd.conf.sample
	install -m 644 etc/nginx/nginx.conf.sample ${SHARE}/etc/nginx/nginx.conf.sample
	install -d ${SSHDCONFDIR}
	install -m 644 etc/ssh/sshd_config.d/gatebsd.conf ${SSHDCONFDIR}/gatebsd.conf
	install -d ${PREFIX}/etc/nginx/conf.d
	install -m 644 etc/nginx/gatebsd-limits.conf ${PREFIX}/etc/nginx/conf.d/gatebsd-limits.conf
	install -d ${PREFIX}/etc/sudoers.d
	install -m 440 etc/sudoers.d/gatebsd-agent ${PREFIX}/etc/sudoers.d/gatebsd-agent
	install -m 644 etc/unbound/unbound.conf.sample ${SHARE}/etc/unbound/unbound.conf.sample
	install -m 600 etc/amnezia/gateway.conf.sample ${SHARE}/etc/amnezia/gateway.conf.sample
	install -m 600 etc/amnezia/direct-exceptions.conf.sample ${SHARE}/etc/amnezia/direct-exceptions.conf.sample
	install -m 640 etc/nut/nut.conf.sample etc/nut/ups.conf.sample etc/nut/upsd.conf.sample etc/nut/upsd.users.sample etc/nut/upsmon.conf.sample ${SHARE}/etc/nut/
	install -m 644 etc/pkg/repos/gatebsd.conf ${SHARE}/etc/pkg/repos/gatebsd.conf
	install -m 444 etc/pkg/keys/gatebsd-stand.pub ${SHARE}/etc/pkg/keys/gatebsd-stand.pub
	@set -eu; eval "$$(LOCALBASE=${PREFIX} sh ci/resolve-python.sh)"; sed "s|%%PYTHON_CMD%%|$$PYTHON_CMD|g" libexec/gatebsd-python.in > ${PREFIX}/libexec/gatebsd-python; chmod 755 ${PREFIX}/libexec/gatebsd-python
	ci/verify-python-tree.sh webui/backend ${SHARE}/webui/backend ${PREFIX}/libexec/gatebsd-python
	install -m 755 rc.d/gatebsd_firstboot ${RCDIR}/gatebsd_firstboot
	install -m 755 rc.d/gatebsd_lock_cleanup ${RCDIR}/gatebsd_lock_cleanup
	install -m 755 rc.d/gatebsd ${RCDIR}/gatebsd
	install -m 755 rc.d/gatebsd_failover ${RCDIR}/gatebsd_failover
	install -m 755 rc.d/ru_bypass ${RCDIR}/ru_bypass
	install -m 755 rc.d/gatewayctl_apply ${RCDIR}/gatewayctl_apply
	install -m 755 rc.d/gatebsd_reverse_ssh ${RCDIR}/gatebsd_reverse_ssh
	install -m 755 sbin/gatewayctl ${SBINDIR}/gatewayctl
	install -m 755 sbin/gatebsd-route-op ${SBINDIR}/gatebsd-route-op
	install -m 755 sbin/gatebsd-port-forward ${SBINDIR}/gatebsd-port-forward
	install -m 755 sbin/gatebsd-reverse-ssh ${SBINDIR}/gatebsd-reverse-ssh
	install -m 755 sbin/gatebsd-watchdog.sh ${SBINDIR}/gatebsd-watchdog.sh
	install -m 755 sbin/gatebsd-healthcheck.sh ${SBINDIR}/gatebsd-healthcheck.sh
	install -m 755 sbin/gatebsd-backup.sh ${SBINDIR}/gatebsd-backup.sh
	install -m 755 sbin/gatebsd-adblock-update.sh ${SBINDIR}/gatebsd-adblock-update.sh
	install -m 755 sbin/gatebsd-ups-health.sh ${SBINDIR}/gatebsd-ups-health.sh
	install -m 755 sbin/gatebsd-renew-ssl ${SBINDIR}/gatebsd-renew-ssl
	install -m 755 sbin/gatebsd-sms-monitor ${SBINDIR}/gatebsd-sms-monitor
	install -m 755 sbin/gatebsd-ups-test.sh ${SBINDIR}/gatebsd-ups-test.sh
	install -m 755 sbin/gatebsd-ups-bootstrap ${SBINDIR}/gatebsd-ups-bootstrap
	install -m 755 sbin/ru-routes.sh ${SBINDIR}/ru-routes.sh
	install -m 755 sbin/ru-bypass-update.sh ${SBINDIR}/ru-bypass-update.sh
	install -m 755 sbin/gatebsd-failoverctl ${SBINDIR}/gatebsd-failoverctl
	install -m 755 sbin/gatebsd-state-value ${SBINDIR}/gatebsd-state-value
	install -m 755 sbin/gatebsd-passwd ${SBINDIR}/gatebsd-passwd
	install -m 755 sbin/gatebsd-scan ${SBINDIR}/gatebsd-scan
	install -m 755 sbin/gatebsd-collect ${SBINDIR}/gatebsd-collect
	install -m 755 sbin/gatebsd-install ${SBINDIR}/gatebsd-install
	install -m 755 sbin/gatebsd-upgrade ${SBINDIR}/gatebsd-upgrade
	install -m 755 sbin/gatebsd-config-guard ${SBINDIR}/gatebsd-config-guard
	install -m 755 sbin/gatebsd-firstboot ${SBINDIR}/gatebsd-firstboot
	install -m 755 sbin/gatebsd-config-migrate ${SBINDIR}/gatebsd-config-migrate
	install -m 755 sbin/gatebsd-lock-cleanup ${SBINDIR}/gatebsd-lock-cleanup
	install -m 755 sbin/gatebsd-repo-bootstrap ${SBINDIR}/gatebsd-repo-bootstrap
	install -m 755 sbin/gatebsd-agentctl ${SBINDIR}/gatebsd-agentctl
	@set -eu; pw groupshow gatebsd >/dev/null 2>&1 || pw groupadd gatebsd; \
	if pw usershow gatebsd >/dev/null 2>&1; then \
	  [ "$$(id -gn gatebsd)" = gatebsd ] && [ "$$(pw usershow gatebsd | awk -F: '{print $$10}')" = /usr/sbin/nologin ] || { echo "Unsafe existing gatebsd account" >&2; exit 1; }; \
	else pw useradd gatebsd -g gatebsd -d /nonexistent -s /usr/sbin/nologin -c "GateBSD service account"; fi
	@set -eu; pw groupshow gatebsd-agent >/dev/null 2>&1 || pw groupadd gatebsd-agent; \
	if pw usershow gatebsd-agent >/dev/null 2>&1; then \
	  [ "$$(id -gn gatebsd-agent)" = gatebsd-agent ] && [ "$$(pw usershow gatebsd-agent | awk -F: '{print $$10}')" = /bin/sh ] || { echo "Unsafe existing gatebsd-agent account" >&2; exit 1; }; \
	else pw useradd gatebsd-agent -g gatebsd-agent -d /home/gatebsd-agent -m -s /bin/sh -c "GateBSD limited automation"; fi
	@set -eu; pw groupshow gatebsd-forward >/dev/null 2>&1 || pw groupadd gatebsd-forward; \
	if pw usershow gatebsd-forward >/dev/null 2>&1; then \
	  [ "$$(id -gn gatebsd-forward)" = gatebsd-forward ] && [ "$$(pw usershow gatebsd-forward | awk -F: '{print $$10}')" = /usr/sbin/nologin ] || { echo "Unsafe existing gatebsd-forward account" >&2; exit 1; }; \
	else pw useradd gatebsd-forward -g gatebsd-forward -d /nonexistent -s /usr/sbin/nologin -c "GateBSD reverse SSH account"; fi
	@set -eu; for d in ${VARDB} ${VARDB_SYSTEM} ${VARRUN} ${ETCDIR}; do [ ! -L "$$d" ] && { [ ! -e "$$d" ] || [ -d "$$d" ]; } || { echo "Unsafe directory: $$d" >&2; exit 1; }; done
	install -d -o gatebsd -g gatebsd -m 0750 ${VARDB}
	install -d -o root -g wheel -m 0750 ${VARDB_SYSTEM}
	install -d -o root -g gatebsd -m 0750 ${VARRUN}
	install -d -o root -g wheel -m 0750 ${ETCDIR}
	@set -eu; d=${ETCDIR}/gatebsd.conf; if [ -e "$$d" ] || [ -L "$$d" ]; then [ -f "$$d" ] && [ ! -L "$$d" ] || exit 1; else install -m 640 etc/gatebsd.conf "$$d"; fi
	@set -eu; d=${ETCDIR}/failover.conf; if [ -e "$$d" ] || [ -L "$$d" ]; then [ -f "$$d" ] && [ ! -L "$$d" ] || exit 1; else install -m 600 etc/gatebsd/failover.conf.sample "$$d"; fi
	@set -eu; d=${ETCDIR}/split-dns.conf; if [ -e "$$d" ] || [ -L "$$d" ]; then [ -f "$$d" ] && [ ! -L "$$d" ] || exit 1; else install -m 600 etc/gatebsd/split-dns.conf.sample "$$d"; fi
	${SBINDIR}/gatebsd-repo-bootstrap --prefix ${PREFIX}
	install -d -o root -g wheel -m 0750 ${PREFIX}/etc/amnezia
	@set -eu; d=${PREFIX}/etc/amnezia/direct-exceptions.conf; if [ -e "$$d" ] || [ -L "$$d" ]; then [ -f "$$d" ] && [ ! -L "$$d" ] || exit 1; else install -m 600 etc/amnezia/direct-exceptions.conf.sample "$$d"; fi
	install -m 644 etc/gatebsd/doh-endpoints ${ETCDIR}/doh-endpoints
	install -m 644 etc/gatebsd/adblock-extra ${ETCDIR}/adblock-extra
	${SBINDIR}/gatebsd-config-migrate
	install -m 644 etc/cron.d/gatebsd-healthcheck ${PREFIX}/etc/cron.d/gatebsd-healthcheck
	install -m 644 etc/cron.d/gatebsd-adblock ${PREFIX}/etc/cron.d/gatebsd-adblock
	install -m 644 etc/cron.d/gatebsd-ups-health ${PREFIX}/etc/cron.d/gatebsd-ups-health
	install -m 644 etc/cron.d/gatebsd-ssl-renew ${PREFIX}/etc/cron.d/gatebsd-ssl-renew
	install -m 644 etc/cron.d/gatebsd-ups-test ${PREFIX}/etc/cron.d/gatebsd-ups-test
	install -m 644 etc/cron.d/gatebsd-sms-monitor ${PREFIX}/etc/cron.d/gatebsd-sms-monitor
	install -m 644 etc/cron.d/ru-bypass ${PREFIX}/etc/cron.d/ru-bypass
	install -m 644 etc/newsyslog.conf.d/gatebsd.conf ${PREFIX}/etc/newsyslog.conf.d/gatebsd.conf
	@${MAKE} install-loader-conf BOOTCONFDIR=${BOOTCONFDIR}
	@echo "Existing PF, routing, DHCP, DNS, PPPoE and AWG configuration preserved."
install-loader-conf:
	scripts/install-loader-conf.sh ${BOOTCONFDIR}
uninstall:
	service gatebsd stop 2>/dev/null || true
	service gatebsd_failover stop 2>/dev/null || true
	service gatebsd_reverse_ssh stop 2>/dev/null || true
	rm -rf ${SHARE}
	rm -f ${RCDIR}/gatebsd_firstboot ${RCDIR}/gatebsd_lock_cleanup ${RCDIR}/gatebsd ${RCDIR}/gatebsd_failover ${RCDIR}/ru_bypass ${RCDIR}/gatewayctl_apply ${RCDIR}/gatebsd_reverse_ssh ${PREFIX}/libexec/gatebsd-python
	rm -f ${SBINDIR}/gatewayctl ${SBINDIR}/gatebsd-route-op ${SBINDIR}/gatebsd-port-forward ${SBINDIR}/gatebsd-reverse-ssh ${SBINDIR}/gatebsd-watchdog.sh ${SBINDIR}/gatebsd-healthcheck.sh ${SBINDIR}/gatebsd-backup.sh ${SBINDIR}/gatebsd-adblock-update.sh
	rm -f ${SBINDIR}/gatebsd-sms-monitor ${SBINDIR}/gatebsd-ups-health.sh ${SBINDIR}/gatebsd-ups-test.sh ${SBINDIR}/gatebsd-ups-bootstrap ${SBINDIR}/gatebsd-renew-ssl ${SBINDIR}/ru-routes.sh ${SBINDIR}/ru-bypass-update.sh ${SBINDIR}/gatebsd-failoverctl ${SBINDIR}/gatebsd-state-value
	rm -f ${SBINDIR}/gatebsd-passwd ${SBINDIR}/gatebsd-scan ${SBINDIR}/gatebsd-collect ${SBINDIR}/gatebsd-install ${SBINDIR}/gatebsd-upgrade ${SBINDIR}/gatebsd-config-guard ${SBINDIR}/gatebsd-firstboot
	rm -f ${SBINDIR}/gatebsd-config-migrate ${SBINDIR}/gatebsd-lock-cleanup ${SBINDIR}/gatebsd-repo-bootstrap ${SBINDIR}/gatebsd-agentctl
	rm -f ${SSHDCONFDIR}/gatebsd.conf ${PREFIX}/etc/sudoers.d/gatebsd-agent ${PREFIX}/etc/nginx/conf.d/gatebsd-limits.conf
	rm -f ${PREFIX}/etc/cron.d/gatebsd-sms-monitor ${PREFIX}/etc/cron.d/gatebsd-healthcheck ${PREFIX}/etc/cron.d/gatebsd-adblock ${PREFIX}/etc/cron.d/gatebsd-ups-health ${PREFIX}/etc/cron.d/gatebsd-ups-test ${PREFIX}/etc/cron.d/gatebsd-ssl-renew ${PREFIX}/etc/cron.d/ru-bypass
	rm -f ${PREFIX}/etc/newsyslog.conf.d/gatebsd.conf
	rm -f ${BOOTCONFDIR}/gatebsd.conf
	@echo "Configuration and database preserved."
check:
	@set -eu; find backup ci deploy infra/freebsd-ci libexec rc.d sbin scripts -type f -print | while IFS= read -r f; do \
	  case "$$(head -n 1 "$$f" 2>/dev/null || true)" in "#!/bin/sh"*|"#!/usr/bin/env sh"*) /bin/sh -n "$$f" ;; esac; \
	done
	@set -eu; find sbin rc.d ci deploy -type f -print | while IFS= read -r f; do \
	  case "$$(head -n 1 "$$f" 2>/dev/null || true)" in "#!"*) [ -x "$$f" ] || { echo "Missing executable mode: $$f" >&2; exit 1; } ;; esac; \
	done
	@find webui/backend/gatebsd_ui -name '*.pyc' -delete; find webui/backend/gatebsd_ui -name __pycache__ -type d -exec rm -rf {} + 2>/dev/null || true
	@set -eu; py="$$(command -v ${PYTHON})"; ci/verify-python-tree.sh webui/backend webui/backend "$$py"
	${PYTHON} -m compileall -q webui/backend/gatebsd_ui
	PYTHONPATH=webui/backend ${PYTHON} -m unittest discover -s tests -v
	@set -eu; git ls-files -s | while read mode hash stage path; do \
	  [ "$$mode" != 100755 ] || [ -x "$$path" ] || { echo "Missing executable mode: $$path" >&2; exit 1; }; \
	done
	@echo "Checks passed"
source-archive:
	scripts/build-source-archive.sh
source-manifest:
	scripts/build-source-manifest.sh
clean:
	find . -name '*.pyc' -delete
	find . -name __pycache__ -type d -exec rm -rf {} + 2>/dev/null || true
