-- Cloud-backed roster storage. No account credentials are included here.
create table if not exists public.roster_accounts (
  username text primary key check (username = lower(username)),
  password_salt text not null check (password_salt ~ '^[0-9a-f]{32}$'),
  password_hash text not null check (password_hash ~ '^[0-9a-f]{64}$'),
  created_at timestamptz not null default now()
);

create table if not exists public.roster_agents (
  username text not null references public.roster_accounts(username) on delete cascade,
  id text not null check (id ~ '^[A-Za-z0-9_-]{1,64}$'),
  name text not null check (char_length(name) between 1 and 60),
  role text not null check (char_length(role) between 1 and 500),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  primary key (username, id)
);

create table if not exists public.roster_login_attempts (
  username text not null,
  ip_hash text not null check (ip_hash ~ '^[0-9a-f]{64}$'),
  attempts integer not null default 0 check (attempts >= 0),
  window_started_at timestamptz not null default now(),
  locked_until timestamptz,
  primary key (username, ip_hash)
);

alter table public.roster_accounts enable row level security;
alter table public.roster_agents enable row level security;
alter table public.roster_login_attempts enable row level security;

revoke all on public.roster_accounts, public.roster_agents, public.roster_login_attempts from anon, authenticated, public;
grant usage on schema public to service_role;
grant select, insert, update, delete on public.roster_accounts, public.roster_agents, public.roster_login_attempts to service_role;
