-- Run this once in the Supabase SQL Editor for the project.

create table public.profiles (
  id uuid primary key references auth.users (id) on delete cascade,
  email text not null default '',
  display_name text not null default '',
  organization text not null default '',
  role text not null default 'user' check (role in ('user', 'admin')),
  created_at timestamptz not null default now()
);

create table public.email_scans (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references public.profiles (id) on delete cascade,
  sender text not null,
  subject text not null default '',
  email_body text not null,
  verdict text not null check (verdict in ('phishing', 'legitimate')),
  threat_category text not null default 'clean' check (
    threat_category in ('credential_harvesting', 'financial_fraud', 'malicious_link', 'social_engineering', 'clean')
  ),
  confidence_percent numeric(4, 1) not null check (confidence_percent between 0 and 100),
  top_terms jsonb not null default '[]'::jsonb,
  created_at timestamptz not null default now()
);

create index email_scans_created_at_idx on public.email_scans (created_at desc);
create index email_scans_user_id_idx on public.email_scans (user_id);

-- New accounts always start as ordinary users. Never accept a role from signup data.
create or replace function public.handle_new_user()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
  insert into public.profiles (id, email)
  values (new.id, coalesce(new.email, ''))
  on conflict (id) do update set email = excluded.email;
  return new;
end;
$$;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created
  after insert or update of email on auth.users
  for each row execute function public.handle_new_user();

-- RLS uses this function to check the current user's role without a recursive policy.
create or replace function public.is_admin()
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select exists (
    select 1 from public.profiles
    where id = (select auth.uid()) and role = 'admin'
  );
$$;

revoke all on function public.is_admin() from public, anon;
grant execute on function public.is_admin() to authenticated;
revoke all on function public.handle_new_user() from public, anon, authenticated;

alter table public.profiles enable row level security;
alter table public.email_scans enable row level security;

revoke all on table public.profiles from anon, authenticated;
revoke all on table public.email_scans from anon, authenticated;
grant select, update (display_name, organization) on public.profiles to authenticated;
grant select, insert (user_id, sender, subject, email_body, verdict, threat_category, confidence_percent, top_terms)
  on public.email_scans to authenticated;

create policy "Users can read their own profile and admins can read profiles"
  on public.profiles for select to authenticated
  using (id = (select auth.uid()) or (select public.is_admin()));

create policy "Users can update their own profile metadata"
  on public.profiles for update to authenticated
  using (id = (select auth.uid()))
  with check (id = (select auth.uid()));

create policy "Users can read their own scans and admins can read all scans"
  on public.email_scans for select to authenticated
  using (user_id = (select auth.uid()) or (select public.is_admin()));

create policy "Users can save scans to their own account"
  on public.email_scans for insert to authenticated
  with check (user_id = (select auth.uid()));

-- Promote an account to admin only after it has registered and confirmed its email.
-- Run manually in the SQL Editor, replacing the address:
-- update public.profiles set role = 'admin' where email = lower('admin@example.com');
