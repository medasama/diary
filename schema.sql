-- ============================================================
-- 日記帳 (diary) : Supabase テーブル設定
-- SQL Editor に貼り付けて「Run」。何度実行しても安全です。
--
-- 方針（C1改：合言葉＋追記専用）
--  - ログインなし。公開キー(anon)で使う
--  - できるのは「読む(SELECT)」と「追加(INSERT)」だけ
--  - 更新(UPDATE)・削除(DELETE)はできない → 他人に消されない
--  - 日記を直すときは「新しい版」を1行追加し、アプリが最新版だけを表示
--  - 見出し・本文・タグ・人物は端末で暗号化済み。ここにあるのは暗号文だけ
-- ============================================================

-- 1) テーブル
create table if not exists "diary-entries" (
  id          bigint generated always as identity primary key,
  day         date not null,                          -- 並び替え・同期用（平文）
  iv          text not null,                          -- 暗号化の初期化ベクトル
  ciphertext  text not null,                          -- 暗号文（見出し・本文・タグ・人物・版の日時）
  created_at  timestamptz not null default now(),
  -- 大量のゴミ行で容量を圧迫されないよう、1行の大きさを制限
  constraint diary_iv_len check (char_length(iv) between 8 and 64),
  constraint diary_ct_len check (char_length(ciphertext) between 16 and 200000)
);

create index if not exists "diary-entries_day_idx" on "diary-entries" (day);

-- 2) RLS（行レベルセキュリティ）を有効化
alter table "diary-entries" enable row level security;

-- 3) 読む・追加する だけを許可（UPDATE / DELETE のポリシーは作らない＝禁止）
drop policy if exists "diary_select" on "diary-entries";
create policy "diary_select" on "diary-entries"
  for select to anon using (true);

drop policy if exists "diary_insert" on "diary-entries";
create policy "diary_insert" on "diary-entries"
  for insert to anon with check (true);

-- 4) 念のため、権限そのものも取り上げる（RLSとの二重の守り）
revoke update, delete, truncate on "diary-entries" from anon, authenticated;

-- 5) created_at を必ずサーバー時刻にする（送られてきた値は無視）
create or replace function diary_force_created_at() returns trigger
language plpgsql as $$
begin
  new.created_at := now();
  return new;
end $$;

drop trigger if exists diary_force_created_at on "diary-entries";
create trigger diary_force_created_at
  before insert on "diary-entries"
  for each row execute function diary_force_created_at();

-- 6) Realtime（他の端末で書いた日記をすぐ反映）
do $$
begin
  if not exists (
    select 1 from pg_publication_tables
    where pubname = 'supabase_realtime'
      and schemaname = 'public'
      and tablename = 'diary-entries'
  ) then
    alter publication supabase_realtime add table "diary-entries";
  end if;
end $$;

-- ------------------------------------------------------------
-- 確認用（任意）：以下が「permission denied」等で失敗すれば正しく守られています
--   update "diary-entries" set day = day;   ← SQL Editorは管理者権限なので成功します。
--   アプリ側（公開キー）からの更新・削除が拒否されることは、アプリの
--   「設定 → 守りの確認」ボタンで確認できます。
-- ------------------------------------------------------------
