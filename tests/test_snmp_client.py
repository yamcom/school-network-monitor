from network_monitor.config import SNMPGlobalConfig, SwitchItemConfig
from network_monitor.snmp.collector import SNMPCollector


class MockFailingSNMPClient:
    def __init__(self, *args, **kwargs):
        pass

    def sync_get(self, oid: str):
        return None

    def sync_walk(self, root_oid: str):
        return []


def test_collector_graceful_timeout_and_error_handling(in_memory_repo):
    repo = in_memory_repo
    collector = SNMPCollector(repo, client_factory=MockFailingSNMPClient)

    sw_cfg = SwitchItemConfig(
        management_ip="192.0.2.254",
        name="UNREACHABLE-SW",
        enabled=True,
    )
    snmp_cfg = SNMPGlobalConfig()

    success = collector.poll_switch(sw_cfg, snmp_cfg)
    assert success is False

    sw = repo.get_switch_by_ip("192.0.2.254")
    assert sw is not None
    assert sw.poll_status == "error"
