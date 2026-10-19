#ifndef PIGEON_STORE_SCHEMA_H
#define PIGEON_STORE_SCHEMA_H

#define SCHEMA_VERSION 2

#define STORE_CONVERSATIONS_SQL \
    "CREATE TABLE conversations (" \
    "us_ip INTEGER NOT NULL CHECK(us_ip BETWEEN 0 AND 4294967295)," \
    "remote_ip INTEGER NOT NULL CHECK(remote_ip BETWEEN 0 AND 4294967295)," \
    "remote_port INTEGER NOT NULL CHECK(remote_port BETWEEN 0 AND 65535)," \
    "protocol INTEGER NOT NULL CHECK(protocol IN (6,17))," \
    "packets_out INTEGER NOT NULL CHECK(typeof(packets_out)='integer' AND packets_out>=0)," \
    "packets_in INTEGER NOT NULL CHECK(typeof(packets_in)='integer' AND packets_in>=0)," \
    "bytes_out INTEGER NOT NULL CHECK(typeof(bytes_out)='integer' AND bytes_out>=0)," \
    "bytes_in INTEGER NOT NULL CHECK(typeof(bytes_in)='integer' AND bytes_in>=0)," \
    "first_seen INTEGER NOT NULL," \
    "last_seen INTEGER NOT NULL CHECK(first_seen<=last_seen)," \
    "remote_name TEXT CHECK(remote_name IS NULL OR length(remote_name) BETWEEN 1 AND 253)," \
    "PRIMARY KEY(us_ip,remote_ip,remote_port,protocol)" \
    ") WITHOUT ROWID;"

#define STORE_DNS_SCHEMA_SQL \
    "CREATE TABLE dns_cache (" \
    "ip INTEGER PRIMARY KEY CHECK(ip BETWEEN 0 AND 4294967295)," \
    "name TEXT NOT NULL CHECK(length(name) BETWEEN 1 AND 253)," \
    "observed_at INTEGER NOT NULL," \
    "expires_at INTEGER NOT NULL CHECK(expires_at>=observed_at)" \
    ");" \
    "CREATE INDEX dns_cache_expiry ON dns_cache(expires_at);" \
    "PRAGMA user_version=2;"

#define STORE_SCHEMA_SQL STORE_CONVERSATIONS_SQL STORE_DNS_SCHEMA_SQL

#define STORE_DNS_UPSERT_SQL \
    "INSERT INTO dns_cache(ip,name,observed_at,expires_at) VALUES(?1,?2,?3,?4)" \
    " ON CONFLICT(ip) DO UPDATE SET name=excluded.name," \
    " observed_at=excluded.observed_at,expires_at=excluded.expires_at" \
    " WHERE excluded.observed_at>=dns_cache.observed_at;"

#define STORE_DNS_LOAD_SQL \
    "SELECT ip,name,observed_at,expires_at FROM dns_cache WHERE expires_at>?1" \
    " ORDER BY observed_at,ip;"

#define STORE_UPSERT_SQL \
    "INSERT INTO conversations (us_ip,remote_ip,remote_port,protocol," \
    "packets_out,packets_in,bytes_out,bytes_in,first_seen,last_seen,remote_name)" \
    " VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)" \
    " ON CONFLICT(us_ip,remote_ip,remote_port,protocol) DO UPDATE SET" \
    " packets_out=conversations.packets_out+excluded.packets_out," \
    " packets_in=conversations.packets_in+excluded.packets_in," \
    " bytes_out=conversations.bytes_out+excluded.bytes_out," \
    " bytes_in=conversations.bytes_in+excluded.bytes_in," \
    " first_seen=min(conversations.first_seen,excluded.first_seen)," \
    " last_seen=max(conversations.last_seen,excluded.last_seen)," \
    " remote_name=coalesce(conversations.remote_name,excluded.remote_name);"

#define STORE_LOOKUP_SQL \
    "SELECT packets_out,packets_in,bytes_out,bytes_in,first_seen,last_seen," \
    "remote_name FROM conversations WHERE us_ip=?1 AND remote_ip=?2" \
    " AND remote_port=?3 AND protocol=?4;"

#endif
