alter table tcp_tls_observations add column if not exists dns_status text;
alter table tcp_tls_observations add column if not exists tls_handshake_ms double precision;
alter table tcp_tls_observations add column if not exists total_connection_ms double precision;
alter table tcp_tls_observations add column if not exists cert_chain_valid boolean not null default false;
