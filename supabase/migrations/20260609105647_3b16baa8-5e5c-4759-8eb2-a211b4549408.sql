
CREATE TABLE public.datasets (
  id UUID NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
  name TEXT NOT NULL,
  source_filename TEXT,
  columns JSONB NOT NULL DEFAULT '[]'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE public.components (
  id UUID NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
  dataset_id UUID NOT NULL REFERENCES public.datasets(id) ON DELETE CASCADE,
  data JSONB NOT NULL DEFAULT '{}'::jsonb,
  content_hash TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (dataset_id, content_hash)
);

CREATE INDEX idx_components_dataset ON public.components(dataset_id);

GRANT SELECT, INSERT, UPDATE, DELETE ON public.datasets TO anon, authenticated;
GRANT ALL ON public.datasets TO service_role;
GRANT SELECT, INSERT, UPDATE, DELETE ON public.components TO anon, authenticated;
GRANT ALL ON public.components TO service_role;

ALTER TABLE public.datasets ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.components ENABLE ROW LEVEL SECURITY;

CREATE POLICY "public read datasets" ON public.datasets FOR SELECT USING (true);
CREATE POLICY "public write datasets" ON public.datasets FOR INSERT WITH CHECK (true);
CREATE POLICY "public update datasets" ON public.datasets FOR UPDATE USING (true) WITH CHECK (true);
CREATE POLICY "public delete datasets" ON public.datasets FOR DELETE USING (true);

CREATE POLICY "public read components" ON public.components FOR SELECT USING (true);
CREATE POLICY "public write components" ON public.components FOR INSERT WITH CHECK (true);
CREATE POLICY "public update components" ON public.components FOR UPDATE USING (true) WITH CHECK (true);
CREATE POLICY "public delete components" ON public.components FOR DELETE USING (true);

CREATE OR REPLACE FUNCTION public.set_updated_at() RETURNS TRIGGER AS $$
BEGIN NEW.updated_at = now(); RETURN NEW; END;
$$ LANGUAGE plpgsql SET search_path = public;

CREATE TRIGGER trg_datasets_updated BEFORE UPDATE ON public.datasets
  FOR EACH ROW EXECUTE FUNCTION public.set_updated_at();
CREATE TRIGGER trg_components_updated BEFORE UPDATE ON public.components
  FOR EACH ROW EXECUTE FUNCTION public.set_updated_at();
