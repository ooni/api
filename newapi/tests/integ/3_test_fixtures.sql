--
-- Data for Name: url_priorities; Type: TABLE DATA; Schema: public; Owner: shovel
--

INSERT INTO public.url_priorities VALUES ('NEWS', '*', '*', '*', 100);
INSERT INTO public.url_priorities VALUES ('POLR', '*', '*', '*', 100);
INSERT INTO public.url_priorities VALUES ('HUMR', '*', '*', '*', 100);
INSERT INTO public.url_priorities VALUES ('LGBT', '*', '*', '*', 100);
INSERT INTO public.url_priorities VALUES ('ANON', '*', '*', '*', 100);
INSERT INTO public.url_priorities VALUES ('MMED', '*', '*', '*', 80);
INSERT INTO public.url_priorities VALUES ('SRCH', '*', '*', '*', 80);
INSERT INTO public.url_priorities VALUES ('PUBH', '*', '*', '*', 80);
INSERT INTO public.url_priorities VALUES ('REL', '*', '*', '*', 60);
INSERT INTO public.url_priorities VALUES ('XED', '*', '*', '*', 60);
INSERT INTO public.url_priorities VALUES ('HOST', '*', '*', '*', 60);
INSERT INTO public.url_priorities VALUES ('ENV', '*', '*', '*', 60);
INSERT INTO public.url_priorities VALUES ('FILE', '*', '*', '*', 40);
INSERT INTO public.url_priorities VALUES ('CULTR', '*', '*', '*', 40);
INSERT INTO public.url_priorities VALUES ('IGO', '*', '*', '*', 40);
INSERT INTO public.url_priorities VALUES ('GOVT', '*', '*', '*', 40);
INSERT INTO public.url_priorities VALUES ('DATE', '*', '*', '*', 30);
INSERT INTO public.url_priorities VALUES ('HATE', '*', '*', '*', 30);
INSERT INTO public.url_priorities VALUES ('MILX', '*', '*', '*', 30);
INSERT INTO public.url_priorities VALUES ('PROV', '*', '*', '*', 30);
INSERT INTO public.url_priorities VALUES ('PORN', '*', '*', '*', 30);
INSERT INTO public.url_priorities VALUES ('GMB', '*', '*', '*', 30);
INSERT INTO public.url_priorities VALUES ('ALDR', '*', '*', '*', 30);
INSERT INTO public.url_priorities VALUES ('GAME', '*', '*', '*', 20);
INSERT INTO public.url_priorities VALUES ('MISC', '*', '*', '*', 20);
INSERT INTO public.url_priorities VALUES ('HACK', '*', '*', '*', 20);
INSERT INTO public.url_priorities VALUES ('ECON', '*', '*', '*', 20);
INSERT INTO public.url_priorities VALUES ('COMM', '*', '*', '*', 20);
INSERT INTO public.url_priorities VALUES ('CTRL', '*', '*', '*', 20);
INSERT INTO public.url_priorities VALUES ('NEWS', 'it', '*', '*', 10);
INSERT INTO public.url_priorities VALUES ('NEWS', 'it', 'www.leggo.it', '*', 5);
INSERT INTO public.url_priorities VALUES ('COMT', '*', '*', '*', 100);
INSERT INTO public.url_priorities VALUES ('GRP', '*', '*', '*', 100);

INSERT INTO public.citizenlab VALUES ('www.theonion.com', 'http://www.theonion.com/', 'ZZ', 'CULTR', 40);

-- Test item in fastpath and jsonl. Found with:
-- SELECT * FROM fastpath
-- WHERE measurement_start_time > '2021-8-1' AND measurement_start_time < '2021-8-9' AND test_name = 'web_connectivity'
-- AND EXISTS ( SELECT 1 FROM jsonl WHERE report_id = fastpath.report_id AND input = fastpath.input) LIMIT 1;

INSERT INTO public.fastpath VALUES ('20210801000007.403848_BR_webconnectivity_a64ce4a5cc068245', '20210731T225551Z_webconnectivity_BR_14868_n1_6Iq5QqbAX9EYx47w', 'https://mail.yahoo.com/', 'BR', 14868, 'web_connectivity', '2021-07-31 22:55:50', '2021-08-01 00:00:01', NULL, '{"blocking_general":1.0,"blocking_global":0.0,"blocking_country":0.0,"blocking_isp":0.0,"blocking_local":0.0,"analysis":{"blocking_type":"dns"}}', 'macos', true, false, false, 'mail.yahoo.com', 'ooniprobe', '2.3.0');

INSERT INTO public.jsonl VALUES ('20210731T225551Z_webconnectivity_BR_14868_n1_6Iq5QqbAX9EYx47w', 'https://mail.yahoo.com/', 'raw/20210801/00/BR/webconnectivity/2021080100_BR_webconnectivity.n0.0.jsonl.gz', 9, NULL);

