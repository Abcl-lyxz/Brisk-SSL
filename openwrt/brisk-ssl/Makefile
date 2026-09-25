# OpenWrt package for Brisk-SSL. Copy this directory into a feed (or package/) of an OpenWrt
# buildroot / SDK, then: make package/brisk-ssl/compile V=s
#
#   libbrisk-ssl   build-only: libbrisk.a + brisk.h / brisk_config.h staged for other packages
#                  (DEPENDS:=+libbrisk-ssl, link with -lbrisk). Nothing lands on the router: the
#                  library is linked statically into whatever uses it.
#   brisk-get      brisk_get / h2_get (and h3_get with the FULL profile): a TLS / HTTP/2 probe for
#                  checking a device's clock, CA bundle and network (docs/TROUBLESHOOTING.md).
#
# Profile: CONFIG_BRISK_SSL_PROFILE (menuconfig -> Libraries -> SSL -> libbrisk-ssl), DEFAULT
# unless changed. SPDX-License-Identifier: Apache-2.0
include $(TOPDIR)/rules.mk

PKG_NAME:=brisk-ssl
PKG_VERSION:=0.1.0
PKG_RELEASE:=1

PKG_SOURCE_PROTO:=git
PKG_SOURCE_URL:=https://github.com/Abcl-lyxz/Brisk-SSL.git
# RELEASE STEP (not done yet: the v0.1.0 tag does not exist): replace both lines below with the
# tag's full 40-hex commit SHA and the hash `make package/brisk-ssl/download V=s` prints, so a
# moved tag or a tampered mirror fails the build. Until then this Makefile is for local testing
# only (make ... USE_SOURCE_DIR=/path/to/Brisk-SSL).
PKG_SOURCE_VERSION:=v$(PKG_VERSION)
PKG_MIRROR_HASH:=skip

PKG_LICENSE:=Apache-2.0
PKG_LICENSE_FILES:=LICENSE NOTICE
PKG_BUILD_PARALLEL:=1
PKG_CONFIG_DEPENDS:=CONFIG_BRISK_SSL_PROFILE

include $(INCLUDE_DIR)/package.mk
include $(INCLUDE_DIR)/cmake.mk

define Package/brisk-ssl/Default
  SECTION:=libs
  CATEGORY:=Libraries
  SUBMENU:=SSL
  URL:=https://github.com/Abcl-lyxz/Brisk-SSL
endef

define Package/libbrisk-ssl
  $(call Package/brisk-ssl/Default)
  TITLE:=Brisk-SSL zero-dependency TLS 1.3/1.2 + QUIC client (static library)
  BUILDONLY:=1
endef

define Package/libbrisk-ssl/description
  Small C99 TLS 1.3 / 1.2 client with optional HTTP/2, QUIC v1 and HTTP/3, for routers and
  gateways. Secure by default: certificate and host name checks always on, AEAD only.
endef

define Package/libbrisk-ssl/config
config BRISK_SSL_PROFILE
	string "Feature profile (TINY, DEFAULT or FULL)"
	depends on PACKAGE_libbrisk-ssl || PACKAGE_brisk-get
	default "DEFAULT"
	help
	  TINY: TLS 1.3 only. DEFAULT: + TLS 1.2, mTLS, HTTP/2. FULL: + QUIC and HTTP/3.
	  Size per profile and arch: docs/CONFIG.md.
endef

define Package/brisk-get
  $(call Package/brisk-ssl/Default)
  SECTION:=utils
  CATEGORY:=Utilities
  TITLE:=TLS / HTTP/2 / HTTP/3 probe built on Brisk-SSL
  DEPENDS:=+ca-bundle
endef

define Package/brisk-get/description
  brisk_get HOST [PORT] prints the TLS version, ALPN and the server's reply; h2_get and h3_get
  do the same over HTTP/2 and HTTP/3 (h3_get needs the FULL profile).
endef

CMAKE_OPTIONS += \
	-DBRISK_PROFILE=$(if $(CONFIG_BRISK_SSL_PROFILE),$(call qstrip,$(CONFIG_BRISK_SSL_PROFILE)),DEFAULT) \
	-DBRISK_BUILD_TESTS=OFF \
	-DBRISK_BUILD_EXAMPLES=ON

define Build/InstallDev
	$(INSTALL_DIR) $(1)/usr/include $(1)/usr/lib
	$(CP) $(PKG_INSTALL_DIR)/usr/include/brisk.h $(PKG_INSTALL_DIR)/usr/include/brisk_config.h \
		$(1)/usr/include/
	$(CP) $(PKG_INSTALL_DIR)/usr/lib/libbrisk.a $(1)/usr/lib/
endef

define Package/brisk-get/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/usr/bin/brisk_get $(PKG_INSTALL_DIR)/usr/bin/h2_get \
		$(1)/usr/bin/
	$(if $(findstring FULL,$(CONFIG_BRISK_SSL_PROFILE)), \
		$(INSTALL_BIN) $(PKG_INSTALL_DIR)/usr/bin/h3_get $(1)/usr/bin/)
endef

$(eval $(call BuildPackage,libbrisk-ssl))
$(eval $(call BuildPackage,brisk-get))
