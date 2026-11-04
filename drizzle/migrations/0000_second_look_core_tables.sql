-- lovable-cron-fallback-reviewed: bounded backstop delete of expired jobs/reports and uploads older than 15 minutes; time-based cleanup required by the privacy promise (uploads deleted within ~15 min), not polling work.
create extension if not exists pg_cron;

create table public.jobs (
  id uuid primary key default gen_random_uuid(),
  type text not null check (type in ('url','screenshot')),
  status text not null default 'queued' check (status in ('queued','running','done','error')),
  stages jsonb not null default '[]'::jsonb,
  result jsonb,
  error_code text,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  expires_at timestamptz not null,
  ip_hash text not null
);

create index jobs_ip_created_idx on public.jobs (ip_hash, created_at);
create index jobs_status_idx on public.jobs (status);
create index jobs_expires_idx on public.jobs (expires_at);

create table public.reports (
  id uuid primary key default gen_random_uuid(),
  input_kind text not null check (input_kind in ('url','screenshot')),
  input_display text not null,
  score int not null,
  classification text not null,
  coverage numeric not null,
  signals jsonb not null default '[]'::jsonb,
  checks jsonb not null default '[]'::jsonb,
  summary text not null default '',
  result jsonb not null,
  delete_token_hash text not null,
  created_at timestamptz not null default now(),
  expires_at timestamptz not null
);

create index reports_expires_idx on public.reports (expires_at);

create table public.rate_limits (
  key text primary key,
  window_start timestamptz not null,
  count int not null default 0
);

grant all on public.jobs to service_role;
grant all on public.reports to service_role;
grant all on public.rate_limits to service_role;

alter table public.jobs enable row level security;
alter table public.reports enable row level security;
alter table public.rate_limits enable row level security;

-- No anon/authenticated policies: all client access goes through the
-- security-definer functions below or the server pipeline.

create extension if not exists pgcrypto;

create or replace function public.get_job(job_id uuid)
returns jsonb
language sql
stable
security definer
set search_path = public
as $$
  select jsonb_build_object(
    'id', j.id,
    'type', j.type,
    'status', j.status,
    'stages', j.stages,
    'result', j.result,
    'error_code', j.error_code,
    'created_at', j.created_at,
    'expires_at', j.expires_at
  )
  from public.jobs j
  where j.id = job_id and j.expires_at > now();
$$;

create or replace function public.get_report(report_id uuid)
returns jsonb
language sql
stable
security definer
set search_path = public
as $$
  select jsonb_build_object(
    'id', r.id,
    'input_kind', r.input_kind,
    'input_display', r.input_display,
    'score', r.score,
    'classification', r.classification,
    'coverage', r.coverage,
    'summary', r.summary,
    'result', r.result,
    'created_at', r.created_at,
    'expires_at', r.expires_at
  )
  from public.reports r
  where r.id = report_id and r.expires_at > now();
$$;

create or replace function public.delete_report(report_id uuid, token text)
returns boolean
language plpgsql
security definer
set search_path = public
as $$
begin
  if exists (
    select 1 from public.reports r
    where r.id = report_id
      and r.delete_token_hash = encode(digest(token, 'sha256'), 'hex')
      and r.expires_at > now()
  ) then
    delete from public.reports where id = report_id;
    return true;
  end if;
  return false;
end;
$$;

create or replace function public.purge_expired()
returns void
language sql
security definer
set search_path = public, storage
as $$
  delete from public.jobs where expires_at < now() - interval '1 hour';
  delete from public.reports where expires_at < now();
  delete from public.rate_limits where window_start < now() - interval '2 days';
  delete from storage.objects where bucket_id = 'uploads' and created_at < now() - interval '15 minutes';
$$;

revoke all on function public.get_job(uuid) from public;
revoke all on function public.get_report(uuid) from public;
revoke all on function public.delete_report(uuid, text) from public;
revoke all on function public.purge_expired() from public;
grant execute on function public.get_job(uuid) to anon, authenticated;
grant execute on function public.get_report(uuid) to anon, authenticated;
grant execute on function public.delete_report(uuid, text) to anon, authenticated;
grant execute on function public.purge_expired() to service_role;

select cron.schedule(
  'second-look-purge-expired',
  '*/10 * * * *',
  $$ select public.purge_expired(); $$
);
