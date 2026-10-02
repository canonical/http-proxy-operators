# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

from django.test import TestCase

import policy.models as models


class ModelsTestCase(TestCase):
    def test_range_set(self):
        left = models.RangeSet([])
        right = models.RangeSet([])
        self.assertTrue(left.is_superset_of(right))
        self.assertFalse(right.overlap(left))

        left = models.RangeSet([])
        right = models.RangeSet([(1, 2)])
        self.assertFalse(left.is_superset_of(right))
        self.assertTrue(right.is_superset_of(left))
        self.assertFalse(left.overlap(right))
        self.assertFalse(right.overlap(left))

        left = models.RangeSet([(0, 10)])
        right = models.RangeSet([(10, 20)])
        self.assertFalse(left.is_superset_of(right))
        self.assertFalse(right.is_superset_of(left))
        self.assertFalse(left.overlap(right))
        self.assertFalse(right.overlap(left))

        left = models.RangeSet([(0, 11)])
        right = models.RangeSet([(10, 20)])
        self.assertFalse(left.is_superset_of(right))
        self.assertFalse(right.is_superset_of(left))
        self.assertTrue(left.overlap(right))
        self.assertTrue(right.overlap(left))

        left = models.RangeSet([(0, 10), (20, 30)])
        right = models.RangeSet([(0, 10), (20, 30)])
        self.assertTrue(left.is_superset_of(right))
        self.assertTrue(right.is_superset_of(left))
        self.assertTrue(left.overlap(right))
        self.assertTrue(right.overlap(left))

        left = models.RangeSet([(0, 10), (20, 30)])
        right = models.RangeSet([(3, 9), (21, 22)])
        self.assertTrue(left.is_superset_of(right))
        self.assertFalse(right.is_superset_of(left))
        self.assertTrue(left.overlap(right))
        self.assertTrue(right.overlap(left))

        left = models.RangeSet([(0, 10), (20, 30)])
        right = models.RangeSet([(29, 30)])
        self.assertTrue(left.is_superset_of(right))
        self.assertTrue(left.overlap(right))
        self.assertTrue(right.overlap(left))

        left = models.RangeSet([(0, 10), (20, 30)])
        right = models.RangeSet([(19, 20)])
        self.assertFalse(left.is_superset_of(right))
        self.assertFalse(left.overlap(right))
        self.assertFalse(right.overlap(left))

    def test_range_set_merge(self):
        range_set = models.RangeSet([(0, 10), (10, 20)])
        self.assertSequenceEqual(range_set._ranges, [(0, 20)])

        range_set = models.RangeSet([(10, 20), (0, 10)])
        self.assertSequenceEqual(range_set._ranges, [(0, 20)])

        range_set = models.RangeSet([(11, 20), (0, 10)])
        self.assertSequenceEqual(range_set._ranges, [(0, 10), (11, 20)])

        range_set = models.RangeSet([(40, 50), (0, 100), (44, 45), (20, 30)])
        self.assertSequenceEqual(range_set._ranges, [(0, 100)])

        range_set = models.RangeSet([(0, 10), (20, 30), (13, 20), (9, 13)])
        self.assertSequenceEqual(range_set._ranges, [(0, 30)])

    def test_range_set_add(self):
        set1 = models.RangeSet([(0, 10), (20, 30)])
        set2 = models.RangeSet([(10, 20)])
        combined = set1 + set2
        self.assertSequenceEqual(combined._ranges, [(0, 30)])

        set1 = models.RangeSet([(0, 10), (20, 30)])
        set2 = models.RangeSet([(5, 15)])
        combined = set1 + set2
        self.assertSequenceEqual(combined._ranges, [(0, 15), (20, 30)])

    def test_ip_set_range(self):
        ip_set = models.IpSet(["2001:beef:cace::/64", "12.34.5.0/30"])
        self.assertSequenceEqual(ip_set.ipv4._ranges, [(203556096, 203556096 + 4)])
        self.assertSequenceEqual(
            ip_set.ipv6._ranges,
            [
                (
                    42544360818096388189859908752443965440,
                    42544360818096388189859908752443965440 + 18446744073709551616,
                )
            ],
        )
        self.assertTrue(ip_set.is_superset_of(models.IpSet(["12.34.5.3"])))
        self.assertFalse(ip_set.overlap(models.IpSet(["12.34.5.4"])))
        self.assertFalse(ip_set.overlap(models.IpSet(["2001:beef:cacf::0"])))

    def test_ip_set_superset(self):
        self.assertTrue(models.IpSet([]).is_superset_of(models.IpSet([])))
        self.assertTrue(models.IpSet(["10.0.0.1"]).is_superset_of(models.IpSet([])))
        self.assertTrue(models.IpSet(["::1"]).is_superset_of(models.IpSet([])))

        set1 = models.IpSet(["10.0.0.0/8", "fe80::/16"])
        set2 = models.IpSet(["10.1.0.0/16", "10.255.255.255", "fe80::1"])
        self.assertTrue(set1.is_superset_of(set2))
        set2 = models.IpSet(["11.2.0.0/16", "fe80::1"])
        self.assertFalse(set1.is_superset_of(set2))
        set2 = models.IpSet(["fe81::1"])
        self.assertFalse(set1.is_superset_of(set2))

    def test_ip_set_overlay(self):
        self.assertFalse(models.IpSet([]).overlap(models.IpSet([])))
        self.assertFalse(models.IpSet(["10.0.0.1"]).overlap(models.IpSet([])))
        self.assertFalse(models.IpSet(["::1"]).overlap(models.IpSet([])))

        set1 = models.IpSet(["10.0.0.0/8", "fe80::/16"])
        set2 = models.IpSet(["10.1.0.0/4"])
        self.assertTrue(set1.overlap(set2))
        self.assertTrue(set2.overlap(set1))

        set1 = models.IpSet(["192.168.1.0/24"])
        set2 = models.IpSet(["192.168.1.128/25", "192.168.2.0/25"])
        self.assertTrue(set1.overlap(set2))
        self.assertFalse(set1.is_superset_of(set2))
        self.assertFalse(set2.is_superset_of(set1))

    def test_ip_set_database_field(self):
        models.Rule.objects.create(
            id=1,
            src_ips=["10.0.0.0/8", "fe80::/16"],
            verdict=models.Verdict.ACCEPT,
        )

        rule = models.Rule.objects.get(id=1)
        self.assertSequenceEqual(rule.src_ips.source, ["10.0.0.0/8", "fe80::/16"])

        self.assertTrue(rule.src_ips.is_superset_of(models.IpSet(["10.0.0.1"])))
        self.assertFalse(rule.src_ips.is_superset_of(models.IpSet(["192.168.0.1"])))
