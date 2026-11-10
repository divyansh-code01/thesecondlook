CREATE TABLE public.known_threats (host text NOT NULL, source text NOT NULL, url text NOT NULL DEFAULT '', fetched_at timestamptz NOT NULL DEFAULT now(), PRIMARY KEY (host, source, url));
GRANT ALL ON public.known_threats TO service_role;
ALTER TABLE public.known_threats ENABLE ROW LEVEL SECURITY;
CREATE INDEX known_threats_host ON public.known_threats (host);
CREATE TABLE public.threat_feed_refresh (source text PRIMARY KEY, fetched_at timestamptz NOT NULL, entry_count integer NOT NULL);
GRANT ALL ON public.threat_feed_refresh TO service_role;
ALTER TABLE public.threat_feed_refresh ENABLE ROW LEVEL SECURITY;