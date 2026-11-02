# MWEB mempool markets

- New option `-maxmempoolmweb=<n>` (0–100, default 80): percentage of `-maxmempool` reserved for MWEB data. Markets may borrow unused space from each other.
- `getmempoolinfo` gains `mwebusage`, `maxmempoolmweb` (bytes), and `mwebminfee` (additional MWEB fee per 1000 MWEB weight above the base fee).
- L1 and MWEB eviction use separate ranking graphs and rolling minimum fees, so cheap MWEB data no longer displaces L1 transactions or spikes `mempoolminfee` to ~400 sat/vB.
- The wallet pays `mwebminfee` (above the base MWEB fee) when building MWEB transactions, so sends are not rejected under MWEB mempool pressure.
