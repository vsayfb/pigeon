#ifndef PIGEON_STORE_SCHEMA_H
#define PIGEON_STORE_SCHEMA_H

#define SCHEMA_VERSION 5

#define STORE_CONVERSATIONS_V2_SQL \
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

#define STORE_DNS_V2_SQL \
    "CREATE TABLE dns_cache (" \
    "ip INTEGER PRIMARY KEY CHECK(ip BETWEEN 0 AND 4294967295)," \
    "name TEXT NOT NULL CHECK(length(name) BETWEEN 1 AND 253)," \
    "observed_at INTEGER NOT NULL," \
    "expires_at INTEGER NOT NULL CHECK(expires_at>=observed_at)" \
    ");" \
    "CREATE INDEX dns_cache_expiry ON dns_cache(expires_at);" \
    "PRAGMA user_version=2;"

#define STORE_CONVERSATIONS_V3_SQL \
    "CREATE TABLE conversations (" \
    "us_ip BLOB NOT NULL CHECK(typeof(us_ip)='blob' AND length(us_ip) IN (4,16))," \
    "remote_ip BLOB NOT NULL CHECK(typeof(remote_ip)='blob' AND length(remote_ip)=length(us_ip))," \
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

#define STORE_CONVERSATIONS_V4_SQL \
    "CREATE TABLE conversations (" \
    "us_ip BLOB NOT NULL CHECK(typeof(us_ip)='blob' AND length(us_ip) IN (4,16))," \
    "remote_ip BLOB NOT NULL CHECK(typeof(remote_ip)='blob' AND length(remote_ip)=length(us_ip))," \
    "remote_port INTEGER NOT NULL CHECK(remote_port BETWEEN 0 AND 65535)," \
    "protocol INTEGER NOT NULL CHECK(protocol IN (6,17))," \
    "packets_out INTEGER NOT NULL CHECK(typeof(packets_out)='integer' AND packets_out>=0)," \
    "packets_in INTEGER NOT NULL CHECK(typeof(packets_in)='integer' AND packets_in>=0)," \
    "bytes_out INTEGER NOT NULL CHECK(typeof(bytes_out)='integer' AND bytes_out>=0)," \
    "bytes_in INTEGER NOT NULL CHECK(typeof(bytes_in)='integer' AND bytes_in>=0)," \
    "first_seen INTEGER NOT NULL," \
    "last_seen INTEGER NOT NULL CHECK(first_seen<=last_seen)," \
    "remote_name TEXT CHECK(remote_name IS NULL OR length(remote_name) BETWEEN 1 AND 253)," \
    "application TEXT NOT NULL CHECK(typeof(application)='text' AND length(CAST(application AS BLOB))<=255)," \
    "PRIMARY KEY(us_ip,remote_ip,remote_port,protocol,application)" \
    ") WITHOUT ROWID;"

#define STORE_CONVERSATIONS_SQL \
    "CREATE TABLE conversations (" \
    "us_ip BLOB NOT NULL CHECK(typeof(us_ip)='blob' AND length(us_ip) IN (4,16))," \
    "remote_ip BLOB NOT NULL CHECK(typeof(remote_ip)='blob' AND length(remote_ip)=length(us_ip))," \
    "remote_port INTEGER NOT NULL CHECK(remote_port BETWEEN 0 AND 65535)," \
    "protocol INTEGER NOT NULL CHECK(protocol IN (1,6,17,58))," \
    "packets_out INTEGER NOT NULL CHECK(typeof(packets_out)='integer' AND packets_out>=0)," \
    "packets_in INTEGER NOT NULL CHECK(typeof(packets_in)='integer' AND packets_in>=0)," \
    "bytes_out INTEGER NOT NULL CHECK(typeof(bytes_out)='integer' AND bytes_out>=0)," \
    "bytes_in INTEGER NOT NULL CHECK(typeof(bytes_in)='integer' AND bytes_in>=0)," \
    "first_seen INTEGER NOT NULL," \
    "last_seen INTEGER NOT NULL CHECK(first_seen<=last_seen)," \
    "remote_name TEXT CHECK(remote_name IS NULL OR length(remote_name) BETWEEN 1 AND 253)," \
    "application TEXT NOT NULL CHECK(typeof(application)='text' AND length(CAST(application AS BLOB))<=255)," \
    "CHECK(protocol IN (6,17) OR (remote_port=0 AND application='' AND " \
    "((protocol=1 AND length(us_ip)=4) OR (protocol=58 AND length(us_ip)=16))))," \
    "PRIMARY KEY(us_ip,remote_ip,remote_port,protocol,application)" \
    ") WITHOUT ROWID;"

#define STORE_DNS_SCHEMA_SQL \
    "CREATE TABLE dns_cache (" \
    "ip BLOB PRIMARY KEY NOT NULL CHECK(typeof(ip)='blob' AND length(ip) IN (4,16))," \
    "name TEXT NOT NULL CHECK(length(name) BETWEEN 1 AND 253)," \
    "observed_at INTEGER NOT NULL," \
    "expires_at INTEGER NOT NULL CHECK(expires_at>=observed_at)" \
    ");" \
    "CREATE INDEX dns_cache_expiry ON dns_cache(expires_at);" \
    "PRAGMA user_version=3;"

#define STORE_MIGRATE_V2_SQL \
    "ALTER TABLE conversations RENAME TO conversations_v2;" \
    "ALTER TABLE dns_cache RENAME TO dns_cache_v2;" \
    "DROP INDEX dns_cache_expiry;" \
    STORE_CONVERSATIONS_V3_SQL STORE_DNS_SCHEMA_SQL \
    "INSERT INTO conversations SELECT ipv4_blob(us_ip),ipv4_blob(remote_ip)," \
    "remote_port,protocol,packets_out,packets_in,bytes_out,bytes_in,first_seen,last_seen," \
    "remote_name FROM conversations_v2;" \
    "INSERT INTO dns_cache SELECT ipv4_blob(ip),name,observed_at,expires_at FROM dns_cache_v2;" \
    "DROP TABLE conversations_v2;DROP TABLE dns_cache_v2;"

#define STORE_MIGRATE_V3_SQL \
    "ALTER TABLE conversations RENAME TO conversations_v3;" \
    STORE_CONVERSATIONS_V4_SQL \
    "INSERT INTO conversations SELECT us_ip,remote_ip,remote_port,protocol," \
    "packets_out,packets_in,bytes_out,bytes_in,first_seen,last_seen,remote_name,''" \
    " FROM conversations_v3;" \
    "DROP TABLE conversations_v3;PRAGMA user_version=4;"

#define STORE_MIGRATE_V4_SQL \
    "ALTER TABLE conversations RENAME TO conversations_v4;" \
    STORE_CONVERSATIONS_SQL \
    "INSERT INTO conversations SELECT * FROM conversations_v4;" \
    "DROP TABLE conversations_v4;PRAGMA user_version=5;"

#define STORE_SCHEMA_SQL STORE_CONVERSATIONS_SQL STORE_DNS_SCHEMA_SQL "PRAGMA user_version=5;"

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
    "packets_out,packets_in,bytes_out,bytes_in,first_seen,last_seen,remote_name,application)" \
    " VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12)" \
    " ON CONFLICT(us_ip,remote_ip,remote_port,protocol,application) DO UPDATE SET" \
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
    " AND remote_port=?3 AND protocol=?4 AND application=?12;"

#endif
