
-- 1) Add owner_id to datasets (nullable first so existing rows survive)
ALTER TABLE public.datasets
  ADD COLUMN IF NOT EXISTS owner_id uuid REFERENCES auth.users(id) ON DELETE CASCADE;

CREATE INDEX IF NOT EXISTS datasets_owner_id_idx ON public.datasets(owner_id);

-- 2) Drop the old permissive public policies on datasets and components
DROP POLICY IF EXISTS "public read datasets"   ON public.datasets;
DROP POLICY IF EXISTS "public write datasets"  ON public.datasets;
DROP POLICY IF EXISTS "public update datasets" ON public.datasets;
DROP POLICY IF EXISTS "public delete datasets" ON public.datasets;

DROP POLICY IF EXISTS "public read components"   ON public.components;
DROP POLICY IF EXISTS "public write components"  ON public.components;
DROP POLICY IF EXISTS "public update components" ON public.components;
DROP POLICY IF EXISTS "public delete components" ON public.components;

-- 3) Revoke broad grants, grant only to authenticated + service_role
REVOKE ALL ON public.datasets    FROM anon, public;
REVOKE ALL ON public.components  FROM anon, public;

GRANT SELECT, INSERT, UPDATE, DELETE ON public.datasets   TO authenticated;
GRANT SELECT, INSERT, UPDATE, DELETE ON public.components TO authenticated;
GRANT ALL ON public.datasets   TO service_role;
GRANT ALL ON public.components TO service_role;

-- 4) Owner-scoped policies on datasets
CREATE POLICY "Owners can read their datasets"
  ON public.datasets FOR SELECT TO authenticated
  USING (owner_id = auth.uid());

CREATE POLICY "Owners can insert their datasets"
  ON public.datasets FOR INSERT TO authenticated
  WITH CHECK (owner_id = auth.uid());

CREATE POLICY "Owners can update their datasets"
  ON public.datasets FOR UPDATE TO authenticated
  USING (owner_id = auth.uid())
  WITH CHECK (owner_id = auth.uid());

CREATE POLICY "Owners can delete their datasets"
  ON public.datasets FOR DELETE TO authenticated
  USING (owner_id = auth.uid());

-- 5) Components inherit ownership from their dataset
CREATE POLICY "Owners can read their components"
  ON public.components FOR SELECT TO authenticated
  USING (EXISTS (
    SELECT 1 FROM public.datasets d
    WHERE d.id = components.dataset_id AND d.owner_id = auth.uid()
  ));

CREATE POLICY "Owners can insert their components"
  ON public.components FOR INSERT TO authenticated
  WITH CHECK (EXISTS (
    SELECT 1 FROM public.datasets d
    WHERE d.id = components.dataset_id AND d.owner_id = auth.uid()
  ));

CREATE POLICY "Owners can update their components"
  ON public.components FOR UPDATE TO authenticated
  USING (EXISTS (
    SELECT 1 FROM public.datasets d
    WHERE d.id = components.dataset_id AND d.owner_id = auth.uid()
  ))
  WITH CHECK (EXISTS (
    SELECT 1 FROM public.datasets d
    WHERE d.id = components.dataset_id AND d.owner_id = auth.uid()
  ));

CREATE POLICY "Owners can delete their components"
  ON public.components FOR DELETE TO authenticated
  USING (EXISTS (
    SELECT 1 FROM public.datasets d
    WHERE d.id = components.dataset_id AND d.owner_id = auth.uid()
  ));

-- 6) Auto-stamp owner_id on insert so the client never has to
CREATE OR REPLACE FUNCTION public.set_dataset_owner()
RETURNS trigger
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = public
AS $$
BEGIN
  IF NEW.owner_id IS NULL THEN
    NEW.owner_id := auth.uid();
  END IF;
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS set_dataset_owner_trigger ON public.datasets;
CREATE TRIGGER set_dataset_owner_trigger
  BEFORE INSERT ON public.datasets
  FOR EACH ROW EXECUTE FUNCTION public.set_dataset_owner();

-- 7) One-time claim function: assigns all orphaned (owner_id IS NULL) datasets
-- to the calling user. Lets the existing dev data be reclaimed after first sign-in
-- without leaving open ownership.
CREATE OR REPLACE FUNCTION public.claim_orphan_datasets()
RETURNS integer
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
  claimed integer;
BEGIN
  IF auth.uid() IS NULL THEN
    RAISE EXCEPTION 'Not authenticated';
  END IF;
  UPDATE public.datasets SET owner_id = auth.uid() WHERE owner_id IS NULL;
  GET DIAGNOSTICS claimed = ROW_COUNT;
  RETURN claimed;
END;
$$;

REVOKE ALL ON FUNCTION public.claim_orphan_datasets() FROM public, anon;
GRANT EXECUTE ON FUNCTION public.claim_orphan_datasets() TO authenticated;
