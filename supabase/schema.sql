-- =====================================================================
-- Brume : équipes, possession des lieux, lieux publics (Supabase / Postgres)
-- À coller dans « SQL Editor » de Supabase, puis « Run ». Réexécutable, et
-- sans danger sur une base créée avec la version précédente (mise à niveau).
--
-- Principe : les joueurs ne peuvent RIEN écrire directement dans « places »,
-- « claim_log » et « reports ». Tout passe par des fonctions qui vérifient côté
-- serveur : connexion, équipe, précision GPS, distance au lieu, vitesse
-- plausible, cadence, délais, quotas, noms.
-- On ne stocke JAMAIS la position du joueur : seulement quel lieu il a touché.
-- Le créateur d'un lieu public et le dernier joueur à y avoir agi ne sont
-- jamais lisibles par les autres joueurs.
--
-- Équipes : codes 't1', 't2', 't3' (les noms et couleurs vivent dans l'app).
-- =====================================================================

-- ---------- tables ----------
create table if not exists public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  pseudo text not null check (pseudo ~ '^[A-Za-z0-9_.-]{3,20}$'),
  team text,
  created_at timestamptz not null default now()
);
create unique index if not exists profiles_pseudo_ci on public.profiles (lower(pseudo));
alter table public.profiles add column if not exists team text;
alter table public.profiles drop constraint if exists profiles_team_check;
alter table public.profiles add constraint profiles_team_check check (team in ('t1', 't2', 't3'));

create table if not exists public.places (
  id text primary key,
  name text not null check (length(name) between 1 and 120),
  lat double precision not null check (lat between -90 and 90),
  lng double precision not null check (lng between -180 and 180),
  cat text not null default '' check (length(cat) <= 20),
  rarity text not null default 'common' check (rarity in ('common', 'rare', 'legend')),
  owner_team text,
  defense real not null default 100,                            -- valeur à l'instant defense_at (elle baisse ensuite avec le temps)
  defense_at timestamptz not null default now(),
  captured_at timestamptz not null default now(),
  reinforced_at timestamptz,
  last_actor uuid references public.profiles(id) on delete set null,
  custom boolean not null default false,                        -- lieu public créé par un joueur
  creator_id uuid references public.profiles(id) on delete set null,
  status text not null default 'active',
  created_at timestamptz not null default now()
);
-- mise à niveau d'une base créée avec la version précédente
alter table public.places add column if not exists owner_team text;
alter table public.places add column if not exists last_actor uuid references public.profiles(id) on delete set null;
alter table public.places add column if not exists custom boolean not null default false;
alter table public.places add column if not exists creator_id uuid references public.profiles(id) on delete set null;
alter table public.places add column if not exists status text not null default 'active';
alter table public.places drop column if exists owner_id;
drop index if exists public.places_owner;
alter table public.places drop constraint if exists places_id_check;
alter table public.places add constraint places_id_check check (id ~ '^([nwr][0-9]{1,15}|c[0-9a-f]{12})$');   -- n/w/r = OpenStreetMap, c = lieu public créé par un joueur
alter table public.places drop constraint if exists places_owner_team_check;
alter table public.places add constraint places_owner_team_check check (owner_team in ('t1', 't2', 't3'));
alter table public.places drop constraint if exists places_status_check;
alter table public.places add constraint places_status_check check (status in ('active', 'hidden', 'removed'));
create index if not exists places_geo on public.places (lat, lng);
create index if not exists places_team on public.places (owner_team);
create index if not exists places_creator on public.places (creator_id) where custom;

create table if not exists public.claim_log (
  id bigserial primary key,
  user_id uuid not null references public.profiles(id) on delete cascade,
  place_id text not null references public.places(id) on delete cascade,
  kind text not null check (kind in ('claim', 'reinforce', 'attack', 'capture')),
  at timestamptz not null default now()
);
create index if not exists claim_log_user_at on public.claim_log (user_id, at desc);
create index if not exists claim_log_user_place on public.claim_log (user_id, place_id, at desc);

create table if not exists public.reports (
  user_id uuid not null references public.profiles(id) on delete cascade,
  place_id text not null references public.places(id) on delete cascade,
  reason text not null default '' check (length(reason) <= 200),
  at timestamptz not null default now(),
  primary key (user_id, place_id)
);

-- l'équipe se choisit une fois et ne change plus
create or replace function public.profiles_lock_team() returns trigger language plpgsql as $$
begin
  if old.team is not null and new.team is distinct from old.team then raise exception 'team_locked'; end if;
  return new;
end $$;
drop trigger if exists profiles_lock_team on public.profiles;
create trigger profiles_lock_team before update on public.profiles for each row execute function public.profiles_lock_team();

-- ---------- sécurité (RLS) ----------
alter table public.profiles enable row level security;
alter table public.places enable row level security;
alter table public.claim_log enable row level security;
alter table public.reports enable row level security;

drop policy if exists profiles_read on public.profiles;
drop policy if exists profiles_insert on public.profiles;
drop policy if exists profiles_update on public.profiles;
drop policy if exists profiles_delete on public.profiles;   -- supprimer son profil permettrait de changer d'équipe : seule delete_account() existe
create policy profiles_read   on public.profiles for select using (true);
create policy profiles_insert on public.profiles for insert with check (id = auth.uid());
create policy profiles_update on public.profiles for update using (id = auth.uid()) with check (id = auth.uid());

drop policy if exists places_read on public.places;
create policy places_read on public.places for select using (true);   -- aucune policy d'écriture : lecture seule

drop policy if exists claim_log_read on public.claim_log;
create policy claim_log_read on public.claim_log for select using (user_id = auth.uid());   -- chacun ne voit que son historique

-- droits explicites (Supabase n'en accorde plus automatiquement aux nouvelles tables)
grant usage on schema public to anon, authenticated;
revoke all on public.profiles, public.places, public.claim_log, public.reports from anon, authenticated;
grant select on public.profiles to anon, authenticated;
grant insert (id, pseudo, team), update (pseudo, team) on public.profiles to authenticated;
grant select (id, name, lat, lng, cat, rarity, owner_team, defense, defense_at, captured_at, custom, status) on public.places to anon, authenticated;   -- ni creator_id ni last_actor
grant select on public.claim_log to authenticated;
grant usage, select on sequence public.claim_log_id_seq to authenticated;

-- ---------- règles du jeu ----------
create or replace function public.dist_m(lat1 double precision, lng1 double precision, lat2 double precision, lng2 double precision)
returns double precision language sql immutable as $$
  select 6371000 * 2 * asin(sqrt(least(1, power(sin(radians(lat2 - lat1) / 2), 2)
    + cos(radians(lat1)) * cos(radians(lat2)) * power(sin(radians(lng2 - lng1) / 2), 2))))
$$;

-- points de défense perdus par jour selon la rareté
create or replace function public.decay_per_day(r text) returns real language sql immutable as $$
  select (case r when 'legend' then 4 when 'rare' then 6 else 10 end)::real
$$;

-- dégâts d'une attaque (plus un lieu est rare, plus il est difficile à ébranler)
create or replace function public.attack_damage(r text) returns real language sql immutable as $$
  select (case r when 'legend' then 25 when 'rare' then 30 else 35 end)::real
$$;

create or replace function public.current_defense(d real, at timestamptz, r text) returns real language sql stable as $$
  select greatest(0, d - public.decay_per_day(r) * extract(epoch from (now() - at)) / 86400.0)::real
$$;

create or replace function public.custom_limit() returns int language sql immutable as $$ select 3 $$;

-- filtre simple des noms offensants (à compléter au besoin)
create or replace function public.bad_name(t text) returns boolean language sql immutable as $$
  select lower(t) ~ '(^|[^a-z])(merde|con|connard|connasse|salope|pute|putain|encule|enculé|nique|ntm|fdp|bite|couille|nazi|hitler|porn|sex|fuck|shit|bitch|cunt|nigg|fag)([^a-z]|$)'
$$;

-- ---------- action principale : prendre / renforcer / attaquer un lieu, au nom de son équipe ----------
create or replace function public.claim_place(
  p_id text, p_name text, p_lat double precision, p_lng double precision, p_cat text, p_rarity text,
  u_lat double precision, u_lng double precision, u_acc double precision
) returns jsonb
language plpgsql security definer set search_path = public as $$
declare
  uid uuid := auth.uid();
  pl public.places%rowtype;
  lp public.places%rowtype;
  last_at timestamptz; last_pid text; since timestamptz;
  cur real; dmg real; nd real;
  secs double precision; moved double precision;
  my_pseudo text; my_team text; prev_team text; existed boolean;
begin
  if uid is null then return jsonb_build_object('ok', false, 'error', 'not_signed_in'); end if;
  select pseudo, team into my_pseudo, my_team from profiles where id = uid;
  if my_pseudo is null then return jsonb_build_object('ok', false, 'error', 'no_profile'); end if;
  if my_team is null then return jsonb_build_object('ok', false, 'error', 'no_team'); end if;
  if p_id is null or p_id !~ '^([nwr][0-9]{1,15}|c[0-9a-f]{12})$' then return jsonb_build_object('ok', false, 'error', 'bad_place'); end if;
  if u_lat is null or u_lng is null or u_acc is null or u_lat not between -90 and 90 or u_lng not between -180 and 180 then
    return jsonb_build_object('ok', false, 'error', 'bad_position'); end if;
  if u_acc > 40 then return jsonb_build_object('ok', false, 'error', 'accuracy'); end if;
  if p_rarity is null or p_rarity not in ('common', 'rare', 'legend') then p_rarity := 'common'; end if;

  -- cadence : 20 actions par heure au maximum
  if (select count(*) from claim_log where user_id = uid and at > now() - interval '1 hour') >= 20 then
    return jsonb_build_object('ok', false, 'error', 'rate_limit'); end if;

  select * into pl from places where id = p_id for update;
  existed := found;   -- FOUND est réécrit par les requêtes suivantes : on le garde à part
  if existed then
    if pl.status <> 'active' then return jsonb_build_object('ok', false, 'error', 'unavailable'); end if;
    if public.dist_m(u_lat, u_lng, pl.lat, pl.lng) > 50 then return jsonb_build_object('ok', false, 'error', 'too_far'); end if;
  else
    -- un lieu inconnu ne peut venir que d'OpenStreetMap : les lieux publics se créent avec create_custom_place()
    if p_id !~ '^[nwr]' then return jsonb_build_object('ok', false, 'error', 'bad_place'); end if;
    if p_lat is null or p_lng is null or p_name is null or length(btrim(p_name)) = 0 then return jsonb_build_object('ok', false, 'error', 'bad_place'); end if;
    if public.dist_m(u_lat, u_lng, p_lat, p_lng) > 50 then return jsonb_build_object('ok', false, 'error', 'too_far'); end if;
  end if;

  -- vitesse plausible entre deux actions (distance entre les deux lieux touchés, jamais la position du joueur)
  select cl.at, cl.place_id into last_at, last_pid from claim_log cl where cl.user_id = uid order by cl.at desc limit 1;
  if last_pid is not null and last_pid <> p_id then
    select * into lp from places where id = last_pid;
    secs := greatest(1, extract(epoch from (now() - last_at)));
    moved := public.dist_m(lp.lat, lp.lng, coalesce(pl.lat, p_lat), coalesce(pl.lng, p_lng));
    if secs < 3600 and moved > 25 and moved / secs > 8 then
      return jsonb_build_object('ok', false, 'error', 'too_fast'); end if;
  end if;

  if not existed then
    -- nouveau lieu : l'équipe du premier qui le touche en devient propriétaire
    insert into places (id, name, lat, lng, cat, rarity, owner_team, defense, defense_at, captured_at, last_actor)
    values (p_id, left(btrim(p_name), 120), p_lat, p_lng, left(coalesce(p_cat, ''), 20), p_rarity, my_team, 100, now(), now(), uid);
    insert into claim_log (user_id, place_id, kind) values (uid, p_id, 'claim');
    return jsonb_build_object('ok', true, 'result', 'claimed', 'defense', 100, 'owner_team', my_team, 'place', p_id);
  end if;

  cur := public.current_defense(pl.defense, pl.defense_at, pl.rarity);

  if pl.owner_team is null then
    update places set owner_team = my_team, defense = 60, defense_at = now(), captured_at = now(), last_actor = uid where id = p_id;
    insert into claim_log (user_id, place_id, kind) values (uid, p_id, 'claim');
    return jsonb_build_object('ok', true, 'result', 'claimed', 'defense', 60, 'owner_team', my_team, 'place', p_id);
  end if;

  if pl.owner_team = my_team then
    -- renforcer : +50 points, une fois par 24 h et par joueur (les équipiers se relaient)
    if cur >= 99.5 then return jsonb_build_object('ok', false, 'error', 'full', 'defense', cur); end if;
    select max(at) into since from claim_log where user_id = uid and place_id = p_id and kind = 'reinforce' and at > now() - interval '24 hours';
    if since is not null then
      return jsonb_build_object('ok', false, 'error', 'already_reinforced', 'defense', cur, 'next_at', since + interval '24 hours'); end if;
    nd := least(100, cur + 50);
    update places set defense = nd, defense_at = now(), reinforced_at = now(), last_actor = uid where id = p_id;
    insert into claim_log (user_id, place_id, kind) values (uid, p_id, 'reinforce');
    return jsonb_build_object('ok', true, 'result', 'reinforced', 'defense', nd, 'owner_team', my_team, 'place', p_id);
  end if;

  -- attaquer : une fois par 24 h et par joueur et par lieu
  if exists (select 1 from claim_log where user_id = uid and place_id = p_id and kind = 'attack' and at > now() - interval '24 hours') then
    return jsonb_build_object('ok', false, 'error', 'cooldown', 'defense', cur); end if;
  prev_team := pl.owner_team;
  dmg := public.attack_damage(pl.rarity);
  nd := cur - dmg;
  if nd <= 0 then
    update places set owner_team = my_team, defense = 60, defense_at = now(), captured_at = now(), reinforced_at = null, last_actor = uid where id = p_id;
    insert into claim_log (user_id, place_id, kind) values (uid, p_id, 'capture');
    return jsonb_build_object('ok', true, 'result', 'captured', 'defense', 60, 'owner_team', my_team, 'previous_team', prev_team, 'place', p_id);
  end if;
  update places set defense = nd, defense_at = now(), last_actor = uid where id = p_id;
  insert into claim_log (user_id, place_id, kind) values (uid, p_id, 'attack');
  return jsonb_build_object('ok', true, 'result', 'attacked', 'defense', nd, 'owner_team', prev_team, 'damage', dmg, 'place', p_id);
end $$;

-- ---------- lieux publics créés par les joueurs ----------
-- Le lieu est créé à la position du joueur (impossible d'en créer un à distance).
create or replace function public.create_custom_place(p_name text, p_cat text, u_lat double precision, u_lng double precision, u_acc double precision)
returns jsonb
language plpgsql security definer set search_path = public as $$
declare
  uid uuid := auth.uid();
  my_pseudo text; my_team text; nm text; new_id text;
begin
  if uid is null then return jsonb_build_object('ok', false, 'error', 'not_signed_in'); end if;
  select pseudo, team into my_pseudo, my_team from profiles where id = uid;
  if my_pseudo is null then return jsonb_build_object('ok', false, 'error', 'no_profile'); end if;
  if my_team is null then return jsonb_build_object('ok', false, 'error', 'no_team'); end if;
  if u_lat is null or u_lng is null or u_acc is null or u_lat not between -90 and 90 or u_lng not between -180 and 180 then
    return jsonb_build_object('ok', false, 'error', 'bad_position'); end if;
  if u_acc > 25 then return jsonb_build_object('ok', false, 'error', 'accuracy'); end if;
  nm := btrim(regexp_replace(coalesce(p_name, ''), '\s+', ' ', 'g'));
  if length(nm) < 3 or length(nm) > 40 or nm ~ '[<>]' or public.bad_name(nm) then return jsonb_build_object('ok', false, 'error', 'bad_name'); end if;
  if p_cat is null or p_cat not in ('commerce', 'cafe', 'nature', 'culture', 'sport', 'coeur') then return jsonb_build_object('ok', false, 'error', 'bad_cat'); end if;
  if (select count(*) from places where creator_id = uid and custom and status in ('active', 'hidden')) >= public.custom_limit() then
    return jsonb_build_object('ok', false, 'error', 'quota', 'limit', public.custom_limit()); end if;
  if exists (select 1 from places where creator_id = uid and custom and created_at > now() - interval '24 hours') then
    return jsonb_build_object('ok', false, 'error', 'create_cooldown'); end if;
  if exists (select 1 from places where status = 'active' and abs(lat - u_lat) < 0.0006 and abs(lng - u_lng) < 0.001
             and public.dist_m(lat, lng, u_lat, u_lng) < 40) then
    return jsonb_build_object('ok', false, 'error', 'too_close'); end if;
  new_id := 'c' || substr(md5(random()::text || clock_timestamp()::text || uid::text), 1, 12);
  insert into places (id, name, lat, lng, cat, rarity, owner_team, defense, defense_at, captured_at, last_actor, custom, creator_id)
  values (new_id, nm, round(u_lat::numeric, 5), round(u_lng::numeric, 5), p_cat, 'common', my_team, 100, now(), now(), uid, true, uid);
  insert into claim_log (user_id, place_id, kind) values (uid, new_id, 'claim');
  return jsonb_build_object('ok', true, 'id', new_id, 'name', nm, 'cat', p_cat, 'owner_team', my_team);
end $$;

create or replace function public.delete_custom_place(p_id text) returns jsonb
language plpgsql security definer set search_path = public as $$
declare n int;
begin
  if auth.uid() is null then return jsonb_build_object('ok', false, 'error', 'not_signed_in'); end if;
  update places set status = 'removed' where id = p_id and custom and creator_id = auth.uid() and status <> 'removed';
  get diagnostics n = row_count;
  if n = 0 then return jsonb_build_object('ok', false, 'error', 'not_found'); end if;
  return jsonb_build_object('ok', true);
end $$;

-- signalement : à 3 signalements de joueurs différents, un lieu public est masqué (à examiner ensuite)
create or replace function public.report_place(p_id text, p_reason text) returns jsonb
language plpgsql security definer set search_path = public as $$
declare uid uuid := auth.uid(); n int;
begin
  if uid is null then return jsonb_build_object('ok', false, 'error', 'not_signed_in'); end if;
  if not exists (select 1 from profiles where id = uid) then return jsonb_build_object('ok', false, 'error', 'no_profile'); end if;
  if not exists (select 1 from places where id = p_id and custom) then return jsonb_build_object('ok', false, 'error', 'not_found'); end if;
  insert into reports (user_id, place_id, reason) values (uid, p_id, left(coalesce(p_reason, ''), 200)) on conflict do nothing;
  select count(*) into n from reports where place_id = p_id;
  if n >= 3 then update places set status = 'hidden' where id = p_id and status = 'active'; end if;
  return jsonb_build_object('ok', true);
end $$;

-- ---------- lectures ----------
drop function if exists public.places_in_bounds(double precision, double precision, double precision, double precision);
drop function if exists public.my_places();
drop function if exists public.leaderboard();

-- lieux possédés dans une zone de la carte (avec la défense actuelle, calculée à la volée)
create or replace function public.places_in_bounds(s double precision, w double precision, n double precision, e double precision)
returns table (id text, name text, lat double precision, lng double precision, cat text, rarity text,
               owner_team text, defense real, custom boolean, captured_at timestamptz)
language sql stable security definer set search_path = public as $$
  select p.id, p.name, p.lat, p.lng, p.cat, p.rarity, p.owner_team,
         public.current_defense(p.defense, p.defense_at, p.rarity), p.custom, p.captured_at
  from places p
  where p.status = 'active' and p.owner_team is not null and p.lat between s and n and p.lng between w and e
  order by p.captured_at desc
  limit 500
$$;

-- les lieux de mon équipe, les plus fragiles d'abord (pour savoir quoi défendre)
create or replace function public.team_places()
returns table (id text, name text, lat double precision, lng double precision, cat text, rarity text, defense real, custom boolean)
language sql stable security definer set search_path = public as $$
  select p.id, p.name, p.lat, p.lng, p.cat, p.rarity, public.current_defense(p.defense, p.defense_at, p.rarity), p.custom
  from places p
  where p.status = 'active' and p.owner_team = (select team from profiles where id = auth.uid())
  order by public.current_defense(p.defense, p.defense_at, p.rarity) asc
  limit 100
$$;

create or replace function public.team_scores()
returns table (team text, places bigint)
language sql stable security definer set search_path = public as $$
  select t.team, count(p.id)
  from (values ('t1'), ('t2'), ('t3')) as t(team)
  left join places p on p.owner_team = t.team and p.status = 'active'
  group by t.team order by count(p.id) desc, t.team
$$;

-- joueurs les plus actifs des 7 derniers jours
create or replace function public.leaderboard()
returns table (pseudo text, team text, points bigint)
language sql stable security definer set search_path = public as $$
  select pr.pseudo, pr.team, sum(case cl.kind when 'capture' then 5 when 'claim' then 3 when 'attack' then 2 else 1 end)::bigint
  from claim_log cl join profiles pr on pr.id = cl.user_id
  where cl.at > now() - interval '7 days'
  group by pr.pseudo, pr.team order by 3 desc, 1 limit 10
$$;

create or replace function public.my_custom_places()
returns table (id text, name text, cat text, status text, owner_team text, defense real)
language sql stable security definer set search_path = public as $$
  select p.id, p.name, p.cat, p.status, p.owner_team, public.current_defense(p.defense, p.defense_at, p.rarity)
  from places p where p.creator_id = auth.uid() and p.custom and p.status in ('active', 'hidden')
  order by p.created_at desc
$$;

-- suppression du compte par son propriétaire (profil, historique ; ses lieux publics sont retirés)
create or replace function public.delete_account() returns void
language plpgsql security definer set search_path = public as $$
begin
  if auth.uid() is null then raise exception 'not_signed_in'; end if;
  update places set status = 'removed' where creator_id = auth.uid() and custom;
  delete from auth.users where id = auth.uid();
end $$;

-- ---------- droits d'exécution ----------
revoke all on function public.claim_place(text, text, double precision, double precision, text, text, double precision, double precision, double precision) from public, anon;
revoke all on function public.create_custom_place(text, text, double precision, double precision, double precision) from public, anon;
revoke all on function public.delete_custom_place(text) from public, anon;
revoke all on function public.report_place(text, text) from public, anon;
revoke all on function public.team_places() from public, anon;
revoke all on function public.my_custom_places() from public, anon;
revoke all on function public.delete_account() from public, anon;
grant execute on function public.claim_place(text, text, double precision, double precision, text, text, double precision, double precision, double precision) to authenticated;
grant execute on function public.create_custom_place(text, text, double precision, double precision, double precision) to authenticated;
grant execute on function public.delete_custom_place(text) to authenticated;
grant execute on function public.report_place(text, text) to authenticated;
grant execute on function public.team_places() to authenticated;
grant execute on function public.my_custom_places() to authenticated;
grant execute on function public.delete_account() to authenticated;
grant execute on function public.places_in_bounds(double precision, double precision, double precision, double precision) to anon, authenticated;
grant execute on function public.team_scores() to anon, authenticated;
grant execute on function public.leaderboard() to anon, authenticated;
