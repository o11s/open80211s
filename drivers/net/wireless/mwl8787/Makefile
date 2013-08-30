mwl8787_sdio-objs := main.o tx.o rx.o cmd.o sdio.o scan.o event.o debugfs.o
mwl8787_sdio-$(CONFIG_NL80211_TESTMODE) += testmode.o

obj-$(CONFIG_MWL8787) += mwl8787_sdio.o

# for tracing
CFLAGS_main.o	:= -I$(src)

ccflags-y += -D__CHECK_ENDIAN__

