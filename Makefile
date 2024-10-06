include $(TOPDIR)/rules.mk

PKG_NAME:=dns-proxy
PKG_RELEASE:=1

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)

include $(INCLUDE_DIR)/package.mk


define Package/dns-proxy
	SECTION:=net
	CATEGORY:=Network
	SUBMENU:=IP Addresses and Names
	TITLE:=DNS requests over a socks proxy
	URL:=https://github.com/cookiengineer/dns-proxy
endef

define Package/dns-proxy/description
	A simple dns proxy to tunnel DNS requests over a socks proxy (for example, over ssh or Tor). This can come in handy when setting up transparent proxies.
	It chooses a random DNS server for each request from the file "resolv.conf" which is a newline delimited list of DNS servers.
	The daemon must be run as root in order for it to bind to port 53.
	Usage: ./dns-proxy [options]
	With no parameters, the configuration file is read from 'dns_proxy.conf'.
	-n -- No configuration file (socks: 127.0.0.1:9050, listener: 0.0.0.0:53).
	-h -- Print this message and exit.
	config_file -- Read from specified configuration file.
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef

define Build/Compile
	$(TARGET_CC) \
	$(TARGET_CFLAGS) \
	$(TARGET_CPPFLAGS) \
	$(FPIC) \
	-o $(PKG_BUILD_DIR)/dns-proxy \
	$(PKG_BUILD_DIR)/dns-proxy.c \
	$(TARGET_LDFLAGS) -pthread
endef

define Package/dns-proxy/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/dns-proxy $(1)/usr/bin/
	$(INSTALL_DIR) $(1)/etc/dns-proxy
	$(INSTALL_DATA) ./files/dns-proxy.conf $(1)/etc/dns-proxy
	$(INSTALL_DATA) ./files/resolv.conf $(1)/etc/dns-proxy
endef

$(eval $(call BuildPackage,dns-proxy))
