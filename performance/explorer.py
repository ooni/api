from locust import HttpLocust, TaskSet, task

class ExplorerTasks(TaskSet):
    @task
    def list_measurements(self):
        self.client.get("/api/v1/measurements")

    @task
    def list_measurements_default(self):
        self.client.get("/api/v1/measurements", params={'until': '2019-09-09', 'limit': 50})

    @task
    def country_page(self):
        """
        http://api.ooni.io/api/_/website_networks?probe_cc=DZ
        http://api.ooni.io/api/_/im_networks?probe_cc=DZ
        http://api.ooni.io/api/_/vanilla_tor_stats?probe_cc=DZ
        http://api.ooni.io/api/_/network_stats?probe_cc=DZ&limit=4&offset=0
        http://api.ooni.io/api/_/website_urls?probe_cc=DZ&probe_asn=36947&limit=5&offset=0

        http://api.ooni.io/api/_/website_stats?probe_cc=DZ&probe_asn=36947&input=http:%2F%2Fwww.emule.com%2F
        http://api.ooni.io/api/_/website_stats?probe_cc=DZ&probe_asn=36947&input=http:%2F%2Fwww.tialsoft.com%2Fdownload%2F
        ... x5
        """
        self.client.get("/api/_/website_networks", params={'probe_cc': 'DZ'})
        self.client.get("/api/_/im_networks", params={'probe_cc': 'DZ'})
        self.client.get("/api/_/im_networks", params={'probe_cc': 'DZ'})
        self.client.get("/api/_/network_stats", params={'probe_cc': 'DZ', 'limit': 4, 'offset': 0})
        self.client.get("/api/_/website_urls", params={'probe_cc': 'DZ', 'probe_asn': 36947})
        self.client.get("/api/_/website_stats", params={'probe_cc': 'DZ', 'probe_asn': 36947, 'input': 'http:%2F%2Fwww.tialsoft.com%2Fdownload%2F'})

    @task
    def search_measurements(self):
        self.client.get("/api/v1/measurements", params={'probe_cc': 'CU', 'domain': 'ooni.io'})


class ExplorerUser(HttpLocust):
    task_set = ExplorerTasks
    min_wait = 5000
    max_wait = 15000
