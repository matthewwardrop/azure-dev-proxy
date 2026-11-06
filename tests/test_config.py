from __future__ import annotations

import argparse
from itertools import permutations
from pathlib import Path
from unittest.mock import patch

import pytest
import idna

from azure_dev_proxy.__main__ import port_number
from azure_dev_proxy.config import Config, TokenRule


class TestConfig:
    def test_hostname_length_boundary(self):
        host = ".".join(["a" * 63] * 3 + ["a" * 61])
        assert len(host) == 253
        assert Config.normalize_host(host) == host
        with pytest.raises(ValueError, match="Invalid hostname") as error:
            Config.normalize_host(host + "a")
        assert isinstance(error.value.__cause__, idna.IDNAError)

    @pytest.mark.parametrize(
        "host",
        ["foo_bar.example", "-foo.example", "foo-.example", "a" * 64 + ".example"],
    )
    def test_idna_rejects_invalid_dns_labels(self, host):
        with pytest.raises(ValueError, match="Invalid hostname") as error:
            Config.normalize_host(host)
        assert isinstance(error.value.__cause__, idna.IDNAError)

    def test_https_resource_selection_requires_a_hostname(self):
        with pytest.raises(ValueError, match="HTTPS destination origin"):
            Config(()).resource_for("https:///foo")

    def test_authority_requires_a_hostname(self):
        with pytest.raises(ValueError, match="Missing destination hostname"):
            Config.normalize_authority(":443")

    def test_wildcards_cannot_target_ipv6_addresses(self):
        with pytest.raises(ValueError, match="Wildcard rules require a DNS suffix"):
            TokenRule("*.::1")

    def test_read_only_file_is_not_replaced(self, tmp_path):
        path = tmp_path / "foo.json"
        original = '{"token_rules":[]}'
        path.write_text(original)
        with (
            patch("azure_dev_proxy.config.os.access", return_value=False),
            pytest.raises(PermissionError, match="not writable"),
        ):
            Config.update_rule(path, TokenRule("foo.example"))
        assert path.read_text() == original
        assert list(tmp_path.iterdir()) == [path]

    def test_temporary_file_creation_failure_preserves_configuration(self, tmp_path):
        path = tmp_path / "foo.json"
        original = '{"token_rules":[]}'
        path.write_text(original)
        with (
            patch(
                "azure_dev_proxy.config.tempfile.NamedTemporaryFile",
                side_effect=OSError("foo"),
            ),
            pytest.raises(OSError, match="foo"),
        ):
            Config.update_rule(path, TokenRule("foo.example"))
        assert path.read_text() == original
        assert list(tmp_path.iterdir()) == [path]

    @pytest.mark.parametrize(
        ("platform", "environment", "relative_root"),
        [
            ("linux", {}, ".config"),
            ("linux", {"XDG_CONFIG_HOME": "custom-config"}, "custom-config"),
            ("linux", {"XDG_CONFIG_HOME": ""}, ".config"),
            ("darwin", {"XDG_CONFIG_HOME": "ignored"}, "Library/Application Support"),
            ("win32", {"APPDATA": "roaming", "XDG_CONFIG_HOME": "ignored"}, "roaming"),
            ("win32", {}, "AppData/Roaming"),
            ("win32", {"APPDATA": ""}, "AppData/Roaming"),
        ],
    )
    def test_native_default_path(
        self, monkeypatch, tmp_path, platform, environment, relative_root
    ):
        monkeypatch.setattr("azure_dev_proxy.config.sys.platform", platform)
        monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))
        for variable in ("APPDATA", "XDG_CONFIG_HOME"):
            monkeypatch.delenv(variable, raising=False)
        for variable, value in environment.items():
            monkeypatch.setenv(variable, str(tmp_path / value) if value else "")
        assert Config.default_path() == (
            tmp_path / relative_root / "azure-dev-proxy" / "config.json"
        )

    def test_explicit_defaults_do_not_replace_instance_rules(self):
        defaults = Config.defaults()
        assert Config.parse(defaults.as_dict()) == defaults
        custom = Config((TokenRule("foo.example", "https://bar.example"),))
        assert custom.resource_for("https://foo.example") == "https://bar.example"
        assert defaults.resource_for("https://foo.example") is None
        assert Config(()).resource_for("https://foo.azure.net") is None
        assert defaults.resource_for("https://foo.azure.net") == "https://foo.azure.net"

    @pytest.mark.parametrize(
        ("host", "resource"),
        [
            ("management.azure.com", "https://management.azure.com/"),
            ("foo.blob.core.windows.net", "https://storage.azure.com/"),
            ("foo.dfs.core.windows.net", "https://storage.azure.com/"),
            ("foo.file.core.windows.net", "https://storage.azure.com/"),
            ("foo.queue.core.windows.net", "https://storage.azure.com/"),
            ("foo.table.core.windows.net", "https://storage.azure.com/"),
            ("foo.vault.azure.net", "https://vault.azure.net/"),
            ("foo.managedhsm.azure.net", "https://managedhsm.azure.net/"),
            ("foo.azconfig.io", "https://appconfig.azure.com"),
            ("foo.servicebus.windows.net", "https://servicebus.azure.net/"),
            ("foo.kusto.windows.net", "https://api.kusto.windows.net"),
            ("foo.search.windows.net", "https://search.azure.com"),
            ("foo.openai.azure.com", "https://cognitiveservices.azure.com/"),
            ("foo.cognitiveservices.azure.com", "https://cognitiveservices.azure.com/"),
            ("foo.dev.azuresynapse.net", "https://dev.azuresynapse.net/"),
            ("foo.bar.ingest.monitor.azure.com", "https://monitor.azure.com/"),
            ("api.loganalytics.io", None),
            ("api.loganalytics.azure.com", "https://api.loganalytics.io"),
            ("api.applicationinsights.io", None),
            ("graph.microsoft.com", None),
            ("foo.sharepoint.com", None),
            ("api.powerbi.com", "https://analysis.windows.net/powerbi/api"),
            ("foo.analysis.windows.net", "https://analysis.windows.net/powerbi/api"),
            ("api.fabric.microsoft.com", None),
            ("onelake.dfs.fabric.microsoft.com", "https://storage.azure.com/"),
            ("dev.azure.com", "https://app.vssps.visualstudio.com"),
            ("foo.visualstudio.com", "https://app.vssps.visualstudio.com"),
        ],
    )
    def test_default_service_audiences_and_https_only_selection(
        self, host, resource, subtests
    ):
        config = Config.defaults()
        for port in ("", ":444"):
            with subtests.test(port=port):
                origin = "https://" + host + port
                assert config.resource_for(origin) == (resource or origin)
                assert config.resource_for("http://" + host + port) is None
        assert config.resource_for("https://" + host + ".bar.example") is None

    def test_specific_defaults_and_exact_event_hubs_override(self):
        config = Config.defaults()
        assert config.resource_for("https://FOO.VAULT.AZURE.NET.:443") == (
            "https://vault.azure.net/"
        )
        override = TokenRule(
            "foo.servicebus.windows.net", "https://eventhubs.azure.net"
        )
        config = Config((*config.token_rules, override))
        assert config.resource_for("https://foo.servicebus.windows.net") == (
            "https://eventhubs.azure.net"
        )
        assert config.resource_for("https://bar.servicebus.windows.net") == (
            "https://servicebus.azure.net/"
        )
        assert config.resource_for("http://foo.servicebus.windows.net") is None

    @pytest.mark.parametrize(
        "host",
        [
            "foo.azure.com",
            "foo.windows.net",
            "foo.microsoft.com",
            "foo.monitor.azure.com",
            "foo.monitoring.azure.com",
            "foo.azurewebsites.net",
            "foo.azurecontainerapps.io",
            "foo.azurestaticapps.net",
            "login.microsoftonline.com",
            "foo.database.windows.net",
            "foo.documents.azure.com",
            "foo.azurecr.io",
            "foo.api.cognitive.microsoft.com",
            "sharepoint.com",
            "foo.graph.microsoft.com",
        ],
    )
    def test_defaults_do_not_allow_broad_domains_or_excluded_services(self, host):
        assert Config.defaults().resource_for("https://" + host) is None

    @pytest.mark.parametrize(
        ("origin", "expected"),
        [
            ("http://[2001:0DB8::1]:80", "http://[2001:db8::1]"),
            ("http://[2001:0DB8::1]:443", "http://[2001:db8::1]:443"),
            ("https://[2001:0DB8::1]:443", "https://[2001:db8::1]"),
            ("https://[2001:0DB8::1]:80", "https://[2001:db8::1]:80"),
        ],
    )
    def test_origin_normalization_preserves_scheme_specific_ipv6_ports(
        self, origin, expected
    ):
        assert Config.normalize_origin(origin) == expected

    def test_non_https_origins_never_select_a_token_resource(self, subtests):
        rules = (
            TokenRule("example.com", "https://shared.example"),
            TokenRule("*.example.com"),
        )
        for origin in (
            "http://example.com",
            "HTTP://example.com:443",
            "http://child.example.com",
            "ftp://example.com",
        ):
            with subtests.test(origin=origin):
                assert Config(rules).resource_for(origin) is None

    def test_wildcards_and_normalization(self):
        rule = TokenRule("*.AZURE.NET.")
        for host in ("foo.azure.net", "foo.bar.azure.net", "FOO.AZURE.NET."):
            assert rule.matches(host)
        for host in (
            "azure.net",
            "notfoo.example",
            "azure.net.bar.example",
            "baz.example",
        ):
            assert not rule.matches(host)
        assert not TokenRule("*.foo.example").matches("notfoo.example")
        assert Config.normalize_host("b\xfccher.example") == "xn--bcher-kva.example"

    def test_resources_are_destination_specific(self):
        rules = (
            TokenRule("foo.azure.net", "https://bar.azure.net"),
            TokenRule("*.azure.net"),
        )
        config = Config(rules)
        assert config.resource_for("https://foo.azure.net") == "https://bar.azure.net"
        assert config.resource_for("https://baz.azure.net") == "https://baz.azure.net"
        assert (
            config.resource_for("https://baz.azure.net:444")
            == "https://baz.azure.net:444"
        )
        assert config.resource_for("https://example.org") is None

    def test_nontransitional_uts46_keeps_distinct_hostnames_separate(self, subtests):
        for host in (
            "fa\u00df.example",
            "FA\u1e9e.Example.",
            "xn--fa-hia.example",
            "fa\u00df\u3002example\u3002",
        ):
            with subtests.test(host=host):
                assert Config.normalize_host(host) == "xn--fa-hia.example"
        assert Config.normalize_host("fass.example") == "fass.example"
        assert Config.normalize_host("\u03c2.example") == "xn--3xa.example"
        assert Config.normalize_host("\u03c3.example") == "xn--4xa.example"
        assert Config.normalize_host("\u039f\u03a3.example") == Config.normalize_host(
            "\u03bf\u03c3.example"
        )
        assert Config.normalize_host("\u039f\u03a3.example") != Config.normalize_host(
            "\u03bf\u03c2.example"
        )
        assert Config.normalize_host("127.0.0.1") == "127.0.0.1"
        assert Config.normalize_host("2001:0DB8:0000::1") == "2001:db8::1"
        for host in ("xn--", "xn--a.example", "a\u200db.example", "a\u200cb.example"):
            with subtests.test(host=host), pytest.raises(ValueError):
                Config.normalize_host(host)

    def test_origins_and_authorities_use_shared_nontransitional_normalization(self):
        assert (
            Config.normalize_authority("fa\xdf.example:444") == "xn--fa-hia.example:444"
        )
        assert (
            Config.normalize_origin("https://fa\xdf.example")
            == "https://xn--fa-hia.example"
        )
        assert Config.normalize_origin("https://fass.example") == "https://fass.example"
        assert (
            Config.normalize_origin("http://fa\xdf.example:443")
            == "http://xn--fa-hia.example:443"
        )
        assert Config.normalize_authority("[2001:0DB8::1]:444") == "[2001:db8::1]:444"
        for normalizer, prefix in (
            (Config.normalize_authority, ""),
            (Config.normalize_origin, "https://"),
        ):
            assert normalizer(prefix + "\u039f\u03a3.example") == normalizer(
                prefix + "\u03bf\u03c3.example"
            )
            assert normalizer(prefix + "\u039f\u03a3.example") != normalizer(
                prefix + "\u03bf\u03c2.example"
            )

    def test_idna_token_rules_do_not_cross_distinct_exact_or_wildcard_hosts(self):
        exact = TokenRule("fa\u00df.example", "https://sharp-s.example")
        wildcard = TokenRule("*.fa\u00df.example", "https://wildcard.example")
        config = Config((wildcard, exact))
        assert exact.host == "xn--fa-hia.example"
        for host in ("fa\u00df.example", "xn--fa-hia.example"):
            assert exact.matches(host)
            assert config.resource_for("https://" + host + ":444") == exact.resource
            assert wildcard.matches("child." + host)
            assert config.resource_for("https://child." + host) == wildcard.resource
        for host in ("fass.example", "child.fass.example"):
            assert config.resource_for("https://" + host) is None
        assert (
            Config((TokenRule("fa\xdf.example"),)).resource_for(
                "https://fa\xdf.example:444"
            )
            == "https://xn--fa-hia.example:444"
        )
        assert Config((TokenRule("\u03bf\u03c3.example"),)).resource_for(
            "https://\u039f\u03a3.example"
        ) == "https://" + Config.normalize_host("\u03bf\u03c3.example")
        audience = "https://fa\u00df.example/audience"
        assert (
            Config((TokenRule("fa\xdf.example", audience),)).resource_for(
                "https://xn--fa-hia.example"
            )
            == audience
        )

    def test_exact_and_longest_suffix_matches_are_independent_of_rule_order(
        self, subtests
    ):
        rules = (
            TokenRule("*.example.com", "https://broad.example"),
            TokenRule("*.dev.example.com", "https://narrow.example"),
            TokenRule("api.dev.example.com", "https://exact.example"),
        )
        for ordered in permutations(rules):
            config = Config(ordered)
            with subtests.test(order=[rule.host for rule in ordered]):
                assert (
                    config.resource_for("https://api.dev.example.com:444")
                    == "https://exact.example"
                )
                assert (
                    config.resource_for("https://other.dev.example.com")
                    == "https://narrow.example"
                )
                assert (
                    config.resource_for("https://other.example.com")
                    == "https://broad.example"
                )
                assert config.resource_for("https://example.com") is None
        for ordered in permutations((rules[0], TokenRule("api.example.com"))):
            assert (
                Config(ordered).resource_for("https://api.example.com:444")
                == "https://api.example.com:444"
            )

    def test_exact_override_precedes_wildcard_rule(self, subtests):
        rules = (
            TokenRule("*.azure-test.net"),
            TokenRule("bar.foo.azure-test.net", "https://foo.azure-test.net"),
        )
        config = Config(rules)
        for origin in (
            "https://bar.foo.azure-test.net",
            "https://BAR.FOO.AZURE-TEST.NET.:443",
            "https://bar.foo.azure-test.net:444",
        ):
            with subtests.test(origin=origin):
                assert config.resource_for(origin) == "https://foo.azure-test.net"
        for origin in (
            "https://foo.azure-test.net",
            "https://foo.azure-test.net:444",
            "https://baz.foo.azure-test.net",
            "https://baz.bar.foo.azure-test.net:444",
            "https://baz.azure-test.net:444",
        ):
            with subtests.test(origin=origin):
                assert Config.defaults().resource_for(origin) == origin
        assert (
            Config.defaults().resource_for("https://bar.foo.azure-test.net.baz.example")
            is None
        )

    def test_defaults_are_limited_to_explicit_domain_suffixes(self, subtests):
        config = Config.defaults()
        for host in (
            "foo.azure.net",
            "foo.azure-test.net",
        ):
            with subtests.test(host=host):
                assert config.resource_for("https://" + host) == "https://" + host
        for host in (
            "azure.net",
            "azure-test.net",
            "baz.example",
            "qux.baz.example",
            "deep.qux.baz.example",
            "qux.baz.invalid",
            "foo.azure.net.bar.example",
            "foo.azure-test.net.bar.example",
            "qux.baz.example.bar.example",
        ):
            with subtests.test(host=host):
                assert config.resource_for("https://" + host) is None

    def test_resource_override_does_not_change_other_hosts(self, subtests):
        rules = (
            TokenRule("*.bar.example"),
            TokenRule("*.azure.net"),
            TokenRule("foo.bar.example", "https://foo.azure.net"),
        )
        config = Config(rules)
        for origin in (
            "https://foo.bar.example",
            "https://FOO.BAR.EXAMPLE.:443",
            "https://foo.bar.example:444",
        ):
            with subtests.test(origin=origin):
                assert config.resource_for(origin) == "https://foo.azure.net"
        for origin in (
            "https://qux.bar.example",
            "https://qux.foo.bar.example",
            "https://bar.foo.azure.net",
            "https://bar.azure.net:444",
        ):
            with subtests.test(origin=origin):
                assert config.resource_for(origin) == origin
        assert config.resource_for("https://foo.bar.example.baz.example") is None

    def test_authority_validation(self, subtests):
        assert Config.normalize_authority("FOO.azure.net.:443") == "foo.azure.net"
        assert Config.normalize_authority("[::1]:444") == "[::1]:444"
        for value in (
            "",
            "user@example.com",
            "example.com:",
            "example.com:0",
            "example.com:65536",
            "example.com/path",
            "example.com?x",
            "example.com%2f",
            "exa mple.com",
            "example.com\\x",
            "-bad.example",
            "a..example",
            "example.com\n",
        ):
            with subtests.test(value=value), pytest.raises(ValueError):
                Config.normalize_authority(value)

    def test_invalid_config_and_ports(self):
        for host in ("*", "*azure.net", "foo.*.net", "*.bar.*"):
            with pytest.raises(ValueError):
                TokenRule(host)
        for resource in ("http://example.com", "https://a/?x=1", "https://user@a/"):
            with pytest.raises(ValueError):
                TokenRule("a", resource)
        assert port_number("8080") == 8080
        for value in ("0", "65536", "no"):
            with pytest.raises(argparse.ArgumentTypeError):
                port_number(value)
