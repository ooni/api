from locust import HttpLocust, TaskSet, task

class ExplorerTasks(TaskSet):
    @task
    def list_measurements(self):
        self.client.get("/api/v1/measurements")

    @task
    def list_measurements_default(self):
        self.client.get("/api/v1/measurements", params={'until': '2019-09-09', 'limit': 50})

    @task
    def country_stats(self):
        probe_cc = 'DZ'
        self.client.get("/api/_/im_networks", params={'probe_cc': probe_cc})
        self.client.get("/api/_/vanilla_tor_stats", params={'probe_cc': probe_cc})
        self.client.get("/api/_/network_stats", params={'probe_cc': probe_cc, 'limit': 4, 'offset': 0})

    @task
    def website_networks(self):
        probe_cc = 'DZ'
        j = self.client.get("/api/_/website_networks", params={'probe_cc': probe_cc}).json()
        if len(j['results']) > 0:
            probe_asn = j['results'][0]['probe_asn']
            j2 = self.client.get("/api/_/website_urls",
                                 params={'probe_cc': probe_cc,
                                         'probe_asn': probe_asn}).json()
            for r in j2['results']:
                self.client.get("/api/_/website_stats",
                                params={'probe_cc': probe_cc,
                                        'probe_asn': probe_asn,
                                        'input': r['input']})

    @task
    def search_measurements(self):
        self.client.get("/api/v1/measurements", params={'probe_cc': 'CU', 'domain': 'ooni.io'})


class ExplorerUser(HttpLocust):
    task_set = ExplorerTasks
    min_wait = 5000
    max_wait = 15000
