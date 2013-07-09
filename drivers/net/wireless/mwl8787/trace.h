#if !defined(__TRACE_MLW8787_H) || defined(TRACE_HEADER_MULTI_READ)
#define __TRACE_MLW8787_H

#include <linux/tracepoint.h>


#if !defined(CONFIG_MWL8787_TRACER) || defined(__CHECKER__)
#undef TRACE_EVENT
#define TRACE_EVENT(name, proto, ...) \
static inline void trace_ ## name(proto) {}
#endif

#undef TRACE_SYSTEM
#define TRACE_SYSTEM mwl8787

TRACE_EVENT(mwl8787_sdio_reg,
	TP_PROTO(struct mwl8787_priv *priv, bool tx, u32 port, u8 val, int ret),
	TP_ARGS(priv, tx, port, val, ret),
	TP_STRUCT__entry(
		__field(struct mwl8787_priv *, priv)
		__field(bool, tx)
		__field(u32, port)
		__field(u8, val)
		__field(int, ret)
	),
	TP_fast_assign(
		__entry->priv = priv;
		__entry->tx = tx;
		__entry->port = port;
		__entry->val = val;
		__entry->ret = ret;
	),
	TP_printk(
		"%s port:0x%x val:0x%x ret:%d", __entry->tx ? "tx" : "rx",
		__entry->port, __entry->val, __entry->ret
	)
);

TRACE_EVENT(mwl8787_sdio,
	TP_PROTO(struct mwl8787_priv *priv, bool tx, u32 port, void *buf, size_t len),
	TP_ARGS(priv, tx, port, buf, len),
	TP_STRUCT__entry(
		__field(struct mwl8787_priv *, priv)
		__field(bool, tx)
		__field(u32, port)
		__field(size_t, len)
		__dynamic_array(u8, buf, len)
	),
	TP_fast_assign(
		__entry->priv = priv;
		__entry->tx = tx;
		__entry->port = port;
		__entry->len = len;
		memcpy(__get_dynamic_array(buf), buf, len);
	),
	TP_printk(
		"%s port:0x%x len:%zd", __entry->tx ? "tx" : "rx",
		__entry->port, __entry->len
	)
);

#endif /* __TRACE_MLW8787_H */

#if defined(CONFIG_MWL8787_TRACER) && !defined(__CHECKER__)

#undef TRACE_INCLUDE_PATH
#define TRACE_INCLUDE_PATH .
#undef TRACE_INCLUDE_FILE
#define TRACE_INCLUDE_FILE trace

#include <trace/define_trace.h>

#endif
