CREATE TABLE public.url_analysis_cache (url_hash text PRIMARY KEY, payload jsonb NOT NULL, expires_at timestamptz NOT NULL);
GRANT ALL ON public.url_analysis_cache TO service_role;
ALTER TABLE public.url_analysis_cache ENABLE ROW LEVEL SECURITY;
CREATE INDEX url_analysis_cache_expiry ON public.url_analysis_cache (expires_at);