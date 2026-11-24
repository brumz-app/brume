-- =====================================================================
-- Brume : possession des lieux (Supabase / Postgres)
-- À coller dans « SQL Editor » de Supabase, puis « Run ». Réexécutable.
--
-- Principe : les joueurs ne peuvent RIEN écrire directement dans les tables
-- « places » et « claim_log ». Tout passe par claim_place(), qui vérifie côté
-- serveur : connexion, précision GPS, distance au lieu, vitesse plausible,
-- cadence maximale, délais entre attaques.
-- On ne stocke JAMAIS la position du joueur : seulement quel lieu il a touché.
-- =====================================================================

-- ---------- tables ----------
create table if not exists public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  pseudo text not null check (pseudo ~ '^[A-Za-z0-9_.-]{3,20}$'),
  created_at timestamptz not null default now()
);
create unique index if not exists profiles_pseudo_ci on public.profiles (lower(pseudo));

create table if not exists public.places (
  id text primary key check (id ~ '^[nwr][0-9]{1,15}$'),      -- identifiant OpenStreetMap (n123, w456, r789)
  name text not null check (length(name) between 1 and 120),
  lat double precision not null check (lat between -90 and 90),
  lng double precision not null check (lng between -180 and 180),
  cat text not null default '' check (length(cat) <= 20),
  rarity text not null default 'common' check (rarity in ('common', 'rare', 'legend')),
  owner_id uuid references public.profiles(id) on delete set null,
  defense real not null default 100,                            -- valeur à l'instant defense_at (elle baisse ensuite avec le temps)
  defense_at timestamptz not null default now(),
  captured_at timestamptz not null default now(),
  reinforced_at timestamptz,
  created_at timestamptz not null default now()
);
create index if not exists places_geo on public.places (lat, lng);
create index if not exists places_owner on public.places (owner_id);

create table if not exists public.claim_log (
  id bigserial primary key,
  user_id uuid not null references public.profiles(id) on delete cascade,
  place_id text not null references public.places(id) on delete cascade,
  kind text not null check (kind in ('claim', 'reinforce', 'attack', 'capture')),
  at timestamptz not null default now()
);
create index if not exists claim_log_user_at on public.claim_log (user_id, at desc);
create index if not exists claim_log_user_place on public.claim_log (user_id, place_id, at desc);

-- ---------- sécurité (RLS) ----------
alter table public.profiles enable row level security;
alter table public.places enable row level security;
alter table public.claim_log enable row level security;

drop policy if exists profiles_read on public.profiles;
drop policy if exists profiles_insert on public.profiles;
drop policy if exists profiles_update on public.profiles;
drop policy if exists profiles_delete on public.profiles;
create policy profiles_read   on public.profiles for select using (true);
create policy profiles_insert on public.profiles for insert with check (id = auth.uid());
create policy profiles_update on public.profiles for update using (id = auth.uid()) with check (id = auth.uid());
create policy profiles_delete on public.profiles for delete using (id = auth.uid());

drop policy if exists places_read on public.places;
create policy places_read on public.places for select using (true);   -- aucune policy d'écriture : lecture seule

drop policy if exists claim_log_read on public.claim_log;
create policy claim_log_read on public.claim_log for select using (user_id = auth.uid());   -- chacun ne voit que son historique

revoke insert, update, delete on public.places, public.claim_log from anon, authenticated;

-- droits explicites (Supabase n'en accorde plus automatiquement aux nouvelles tables)
grant usage on schema public to anon, authenticated;
grant select on public.profiles to anon, authenticated;
grant insert, update, delete on public.profiles to authenticated;
grant select on public.places to anon, authenticated;
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

-- ---------- action principale : prendre / renforcer / attaquer un lieu ----------
create or replace function public.claim_place(
  p_id text, p_name text, p_lat double precision, p_lng double precision, p_cat text, p_rarity text,
  u_lat double precision, u_lng double precision, u_acc double precision
) returns jsonb
language plpgsql security definer set search_path = public as $$
declare
  uid uuid := auth.uid();
  pl public.places%rowtype;
  lp public.places%rowtype;
  last_at timestamptz; last_pid text;
  cur real; dmg real; nd real;
  secs double precision; moved double precision;
  prev_owner text; me_pseudo text; existed boolean;
begin
  if uid is null then return jsonb_build_object('ok', false, 'error', 'not_signed_in'); end if;
  select pseudo into me_pseudo from profiles where id = uid;
  if me_pseudo is null then return jsonb_build_object('ok', false, 'error', 'no_profile'); end if;
  if p_id is null or p_id !~ '^[nwr][0-9]{1,15}$' then return jsonb_build_object('ok', false, 'error', 'bad_place'); end if;
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
    if public.dist_m(u_lat, u_lng, pl.lat, pl.lng) > 50 then return jsonb_build_object('ok', false, 'error', 'too_far'); end if;
  else
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
    -- nouveau lieu : le premier qui le touche en devient propriétaire
    insert into places (id, name, lat, lng, cat, rarity, owner_id, defense, defense_at, captured_at, reinforced_at)
    values (p_id, left(btrim(p_name), 120), p_lat, p_lng, left(coalesce(p_cat, ''), 20), p_rarity, uid, 100, now(), now(), now());
    insert into claim_log (user_id, place_id, kind) values (uid, p_id, 'claim');
    return jsonb_build_object('ok', true, 'result', 'claimed', 'defense', 100, 'owner', me_pseudo, 'place', p_id);
  end if;

  cur := public.current_defense(pl.defense, pl.defense_at, pl.rarity);

  if pl.owner_id is null then
    update places set owner_id = uid, defense = 60, defense_at = now(), captured_at = now(), reinforced_at = null where id = p_id;
    insert into claim_log (user_id, place_id, kind) values (uid, p_id, 'claim');
    return jsonb_build_object('ok', true, 'result', 'claimed', 'defense', 60, 'owner', me_pseudo, 'place', p_id);
  end if;

  if pl.owner_id = uid then
    -- renforcer : une fois par 24 h
    if pl.reinforced_at is not null and now() - pl.reinforced_at < interval '24 hours' then
      return jsonb_build_object('ok', false, 'error', 'already_reinforced', 'defense', cur, 'next_at', pl.reinforced_at + interval '24 hours'); end if;
    update places set defense = 100, defense_at = now(), reinforced_at = now() where id = p_id;
    insert into claim_log (user_id, place_id, kind) values (uid, p_id, 'reinforce');
    return jsonb_build_object('ok', true, 'result', 'reinforced', 'defense', 100, 'owner', me_pseudo, 'place', p_id);
  end if;

  -- attaquer : une fois par 24 h et par lieu
  if exists (select 1 from claim_log where user_id = uid and place_id = p_id and kind = 'attack' and at > now() - interval '24 hours') then
    return jsonb_build_object('ok', false, 'error', 'cooldown', 'defense', cur); end if;
  select pseudo into prev_owner from profiles where id = pl.owner_id;
  dmg := public.attack_damage(pl.rarity);
  nd := cur - dmg;
  if nd <= 0 then
    update places set owner_id = uid, defense = 60, defense_at = now(), captured_at = now(), reinforced_at = null where id = p_id;
    insert into claim_log (user_id, place_id, kind) values (uid, p_id, 'capture');
    return jsonb_build_object('ok', true, 'result', 'captured', 'defense', 60, 'owner', me_pseudo, 'previous_owner', prev_owner, 'place', p_id);
  end if;
  update places set defense = nd, defense_at = now() where id = p_id;
  insert into claim_log (user_id, place_id, kind) values (uid, p_id, 'attack');
  return jsonb_build_object('ok', true, 'result', 'attacked', 'defense', nd, 'owner', prev_owner, 'damage', dmg, 'place', p_id);
end $$;

-- ---------- lectures ----------
-- lieux possédés dans une zone de la carte (avec la défense actuelle, calculée à la volée)
create or replace function public.places_in_bounds(s double precision, w double precision, n double precision, e double precision)
returns table (id text, name text, lat double precision, lng double precision, cat text, rarity text,
               owner_id uuid, owner text, defense real, captured_at timestamptz)
language sql stable security definer set search_path = public as $$
  select p.id, p.name, p.lat, p.lng, p.cat, p.rarity, p.owner_id, pr.pseudo,
         public.current_defense(p.defense, p.defense_at, p.rarity), p.captured_at
  from places p join profiles pr on pr.id = p.owner_id
  where p.lat between s and n and p.lng between w and e
  order by p.captured_at desc
  limit 500
$$;

create or replace function public.my_places()
returns table (id text, name text, lat double precision, lng double precision, cat text, rarity text,
               defense real, captured_at timestamptz, can_reinforce boolean)
language sql stable security definer set search_path = public as $$
  select p.id, p.name, p.lat, p.lng, p.cat, p.rarity,
         public.current_defense(p.defense, p.defense_at, p.rarity), p.captured_at,
         (p.reinforced_at is null or now() - p.reinforced_at >= interval '24 hours')
  from places p where p.owner_id = auth.uid()
  order by p.captured_at desc
$$;

create or replace function public.leaderboard()
returns table (pseudo text, places bigint)
language sql stable security definer set search_path = public as $$
  select pr.pseudo, count(*) from places p join profiles pr on pr.id = p.owner_id
  group by pr.pseudo order by count(*) desc, pr.pseudo limit 20
$$;

-- suppression du compte par son propriétaire (profil, historique ; les lieux redeviennent libres)
create or replace function public.delete_account() returns void
language plpgsql security definer set search_path = public as $$
begin
  if auth.uid() is null then raise exception 'not_signed_in'; end if;
  delete from auth.users where id = auth.uid();
end $$;

-- ---------- droits d'exécution ----------
revoke all on function public.claim_place(text, text, double precision, double precision, text, text, double precision, double precision, double precision) from public, anon;
revoke all on function public.my_places() from public, anon;
revoke all on function public.delete_account() from public, anon;
grant execute on function public.claim_place(text, text, double precision, double precision, text, text, double precision, double precision, double precision) to authenticated;
grant execute on function public.my_places() to authenticated;
grant execute on function public.delete_account() to authenticated;
grant execute on function public.places_in_bounds(double precision, double precision, double precision, double precision) to anon, authenticated;
grant execute on function public.leaderboard() to anon, authenticated;
