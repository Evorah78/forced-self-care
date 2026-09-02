insert into public.fsc_medications (name, sort_order) values
  ('Turmeric', 6),
  ('Vitamin C', 7),
  ('Multivitamin', 8),
  ('Oil of Oregano', 9)
on conflict (name) do update
set sort_order = excluded.sort_order,
    active = true;
